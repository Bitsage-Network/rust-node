//! # Job Coordinator
//!
//! The coordinator is responsible for:
//! - Receiving job requests from clients
//! - Analyzing job requirements and splitting them into parallel tasks
//! - Distributing tasks to available workers
//! - Collecting and assembling results
//! - Managing job lifecycle and payment distribution

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use anyhow::{Result, anyhow};
use tracing::{info, debug, warn};
use starknet::core::types::FieldElement;

use crate::types::{JobId, WorkerId, TaskId};
pub use crate::types::WorkerCapabilities; // Re-export for backward compatibility
use crate::blockchain::contracts::JobManagerContract;
use crate::storage::Database;
use crate::coordinator::config::BlockchainConfig;
use crate::obelysk::elgamal::ECPoint;
use crate::obelysk::payment_client::PaymentRouterClient;
use crate::obelysk::proof_compression::CompressedProof;
use crate::obelysk::privacy_swap::AssetId;

/// Job types that can be parallelized
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JobType {
    /// 3D rendering job
    Render3D {
        scene_file: String,
        output_resolution: (u32, u32),
        frames: Option<u32>,
        quality_preset: String,
    },
    /// Video processing job
    VideoProcessing {
        input_file: String,
        output_format: String,
        resolution: (u32, u32),
        frame_rate: f32,
        duration: f32,
    },
    /// Basic AI inference job
    AIInference {
        model_type: String,
        input_data: String,
        batch_size: u32,
        parameters: HashMap<String, serde_json::Value>,
    },
    /// Computer Vision jobs
    ComputerVision {
        task_type: CVTaskType,
        model_name: String,
        input_images: Vec<String>,
        output_format: String,
        confidence_threshold: f32,
        batch_size: u32,
        additional_params: HashMap<String, serde_json::Value>,
    },
    /// Natural Language Processing jobs
    NLP {
        task_type: NLPTaskType,
        model_name: String,
        input_text: Vec<String>,
        max_tokens: u32,
        temperature: f32,
        context_window: u32,
        additional_params: HashMap<String, serde_json::Value>,
    },
    /// Audio processing jobs
    AudioProcessing {
        task_type: AudioTaskType,
        model_name: String,
        input_audio: Vec<String>,
        sample_rate: u32,
        output_format: String,
        additional_params: HashMap<String, serde_json::Value>,
    },
    /// Time series analysis and forecasting
    TimeSeriesAnalysis {
        task_type: TimeSeriesTaskType,
        model_name: String,
        input_data: Vec<f64>,
        forecast_horizon: u32,
        confidence_intervals: bool,
        features: Vec<String>,
        additional_params: HashMap<String, serde_json::Value>,
    },
    /// Multimodal AI jobs
    MultimodalAI {
        task_type: MultimodalTaskType,
        model_name: String,
        text_input: Option<String>,
        image_input: Option<String>,
        audio_input: Option<String>,
        video_input: Option<String>,
        output_modality: String,
        additional_params: HashMap<String, serde_json::Value>,
    },
    /// Reinforcement Learning jobs
    ReinforcementLearning {
        task_type: RLTaskType,
        environment: String,
        algorithm: String,
        training_steps: u64,
        model_architecture: String,
        hyperparameters: HashMap<String, f64>,
        checkpoint_frequency: u32,
    },
    /// Specialized AI domains
    SpecializedAI {
        domain: AIDomain,
        task_type: String,
        model_name: String,
        input_data: serde_json::Value,
        domain_specific_params: HashMap<String, serde_json::Value>,
        computational_requirements: ComputeRequirements,
    },
    /// Zero-knowledge proof generation
    ZKProof {
        circuit_type: String,
        input_data: String,
        proof_system: String,
    },
    /// Custom compute job
    Custom {
        docker_image: String,
        command: Vec<String>,
        input_files: Vec<String>,
        parallelizable: bool,
    },
    /// Data pipeline job (Confidential Data Plane)
    DataPipeline {
        sql_query: String,
        data_source: String,
        tee_required: bool,
    },
    /// Confidential VM job
    ConfidentialVM {
        image_url: String,
        memory_mb: u32,
        vcpu_count: u32,
        tee_type: String, // "TDX", "SEV-SNP"
    },
}

impl std::fmt::Display for JobType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JobType::Render3D { .. } => write!(f, "Render3D"),
            JobType::VideoProcessing { .. } => write!(f, "VideoProcessing"),
            JobType::AIInference { .. } => write!(f, "AIInference"),
            JobType::ComputerVision { .. } => write!(f, "ComputerVision"),
            JobType::NLP { .. } => write!(f, "NLP"),
            JobType::AudioProcessing { .. } => write!(f, "AudioProcessing"),
            JobType::TimeSeriesAnalysis { .. } => write!(f, "TimeSeriesAnalysis"),
            JobType::MultimodalAI { .. } => write!(f, "MultimodalAI"),
            JobType::ReinforcementLearning { .. } => write!(f, "ReinforcementLearning"),
            JobType::SpecializedAI { .. } => write!(f, "SpecializedAI"),
            JobType::ZKProof { .. } => write!(f, "ZKProof"),
            JobType::Custom { .. } => write!(f, "Custom"),
            JobType::DataPipeline { .. } => write!(f, "DataPipeline"),
            JobType::ConfidentialVM { .. } => write!(f, "ConfidentialVM"),
        }
    }
}

/// Computer Vision task types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CVTaskType {
    ObjectDetection,
    ImageClassification,
    ImageSegmentation,
    FaceRecognition,
    FaceDetection,
    OCR,
    ImageGeneration,
    StyleTransfer,
    SuperResolution,
    ImageCaptioning,
    VisualQuestionAnswering,
    SceneUnderstanding,
    DepthEstimation,
    PoseEstimation,
    Custom(String),
}

/// Natural Language Processing task types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NLPTaskType {
    SentimentAnalysis,
    TextClassification,
    NamedEntityRecognition,
    TextSummarization,
    QuestionAnswering,
    Translation,
    TextGeneration,
    EmbeddingsGeneration,
    CodeGeneration,
    CodeCompletion,
    ConversationalAI,
    TextToSpeech,
    LanguageModeling,
    TokenClassification,
    Custom(String),
}

/// Audio processing task types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AudioTaskType {
    SpeechToText,
    TextToSpeech,
    AudioClassification,
    MusicGeneration,
    AudioEnhancement,
    NoiseReduction,
    SpeakerIdentification,
    AudioTranscription,
    MusicInformationRetrieval,
    AudioSeparation,
    VoiceConversion,
    Custom(String),
}

/// Time series analysis task types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TimeSeriesTaskType {
    Forecasting,
    AnomalyDetection,
    TrendAnalysis,
    SeasonalDecomposition,
    ChangePointDetection,
    Clustering,
    Classification,
    Regression,
    Custom(String),
}

/// Multimodal AI task types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MultimodalTaskType {
    ImageCaptioning,
    VisualQuestionAnswering,
    VideoUnderstanding,
    CrossModalRetrieval,
    MultimodalEmbeddings,
    AudioVisualSpeechRecognition,
    VideoSummarization,
    MultimodalSentimentAnalysis,
    Custom(String),
}

/// Reinforcement Learning task types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RLTaskType {
    PolicyOptimization,
    ValueFunctionApproximation,
    ModelBasedRL,
    ModelFreeRL,
    MultiAgentRL,
    HierarchicalRL,
    InverseRL,
    ImitationLearning,
    Custom(String),
}

/// Specialized AI domains
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AIDomain {
    Medical,
    Scientific,
    Robotics,
    AutonomousSystems,
    ClimateModeling,
    Bioinformatics,
    DrugDiscovery,
    MaterialsScience,
    Astronomy,
    Finance,
    Cybersecurity,
    Custom(String),
}

/// Computational requirements for specialized AI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeRequirements {
    pub min_gpu_memory_gb: u32,
    pub min_cpu_cores: u32,
    pub min_ram_gb: u32,
    pub preferred_gpu_type: Option<String>,
    pub requires_high_precision: bool,
    pub requires_specialized_hardware: bool,
    pub estimated_runtime_minutes: u32,
}

/// Parallelization strategy for different job types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ParallelizationStrategy {
    /// Split by video frames
    FrameBased {
        total_frames: u32,
        frames_per_chunk: u32,
    },
    /// Split by image tiles
    TileBased {
        image_width: u32,
        image_height: u32,
        tile_size: (u32, u32),
    },
    /// Split by data chunks
    ChunkBased {
        total_size: u64,
        chunk_size: u64,
    },
    /// Split by batch processing
    BatchBased {
        total_items: u32,
        batch_size: u32,
    },
    /// No parallelization needed
    Sequential,
}

/// Individual task within a job
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub id: TaskId,
    pub job_id: JobId,
    pub task_type: JobType,
    pub input_data: TaskInput,
    pub dependencies: Vec<TaskId>,
    pub estimated_duration: u64, // seconds
    pub estimated_memory: u64,   // MB
    pub gpu_required: bool,
    pub priority: u8,
    pub status: TaskStatus,
    pub assigned_worker: Option<WorkerId>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Task input data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskInput {
    pub parameters: HashMap<String, serde_json::Value>,
    pub files: Vec<String>,
    pub chunk_info: Option<ChunkInfo>,
}

/// Information about data chunks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkInfo {
    pub chunk_id: u32,
    pub total_chunks: u32,
    pub start_offset: u64,
    pub end_offset: u64,
    pub frame_range: Option<(u32, u32)>,
    pub tile_coords: Option<(u32, u32, u32, u32)>, // x, y, width, height
}

/// Task execution status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TaskStatus {
    Pending,
    Queued,
    Assigned,
    Running,
    Completed,
    Failed,
    Cancelled,
}

/// Job coordination result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobResult {
    pub job_id: JobId,
    pub status: JobStatus,
    pub completed_tasks: u32,
    pub total_tasks: u32,
    pub output_files: Vec<String>,
    pub execution_time: u64,
    pub total_cost: u64,
    pub error_message: Option<String>,

    // ZK Proof data
    /// Blake3 hash of the proof for on-chain commitment
    pub proof_hash: Option<[u8; 32]>,
    /// 32-byte proof attestation
    pub proof_attestation: Option<[u8; 32]>,
    /// Proof commitment for on-chain verification
    pub proof_commitment: Option<[u8; 32]>,
    /// Compressed proof for on-chain submission
    pub compressed_proof: Option<CompressedProof>,
    /// Proof size in bytes (before compression)
    pub proof_size_bytes: Option<usize>,
    /// Proof generation time in milliseconds
    pub proof_time_ms: Option<u64>,
}

/// Overall job status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum JobStatus {
    Pending,
    Submitted,
    Analyzing,
    Queued,
    Running,
    Assembling,
    Completed,
    Failed,
    Cancelled,
}

/// Job submission request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobRequest {
    pub job_type: JobType,
    pub priority: u8,
    pub max_cost: u64,
    pub deadline: Option<chrono::DateTime<chrono::Utc>>,
    pub client_address: String,
    pub callback_url: Option<String>,
    pub data: Vec<u8>,
    pub max_duration_secs: u64,
}

/// Privacy payment configuration for coordinator
#[derive(Debug, Clone)]
pub struct PrivacyPaymentConfig {
    /// Enable encrypted privacy payments
    pub enabled: bool,
    /// Starknet RPC URL for payment transactions
    pub starknet_rpc_url: Option<String>,
    /// Coordinator's Starknet private key (hex, no 0x prefix)
    pub starknet_private_key: Option<String>,
    /// Coordinator's Starknet account address
    pub starknet_account_address: Option<String>,
    /// Payment router contract address
    pub payment_router_address: Option<String>,
    /// Base payment rate per task (in smallest token units)
    /// Kept for backward compatibility - uses SAGE rate
    pub base_payment_rate: u128,
    /// Per-asset payment rates (asset_id -> rate per task)
    /// Allows different rates for SAGE, USDC, STRK, BTC
    pub base_payment_rates: HashMap<AssetId, u128>,
    /// Default asset for payments when not specified
    pub default_payment_asset: AssetId,
}

impl Default for PrivacyPaymentConfig {
    fn default() -> Self {
        let mut base_rates = HashMap::new();
        // Default rates in smallest units:
        // - SAGE: 100 (18 decimals) = 100 wei
        // - USDC: 100 (6 decimals) = $0.0001
        // - STRK: 100 (18 decimals) = 100 wei
        // - BTC: 1 (8 decimals) = 0.00000001 BTC (1 sat)
        base_rates.insert(AssetId::SAGE, 100);
        base_rates.insert(AssetId::USDC, 100);
        base_rates.insert(AssetId::STRK, 100);
        base_rates.insert(AssetId::BTC, 1);

        Self {
            enabled: false,
            starknet_rpc_url: None,
            starknet_private_key: None,
            starknet_account_address: None,
            payment_router_address: None,
            base_payment_rate: 100, // Legacy SAGE rate
            base_payment_rates: base_rates,
            default_payment_asset: AssetId::SAGE,
        }
    }
}

/// Main coordinator service
pub struct JobCoordinator {
    database: Arc<Database>,
    job_manager: Arc<JobManagerContract>,
    blockchain_config: BlockchainConfig,
    active_jobs: Arc<RwLock<HashMap<JobId, JobState>>>,
    task_queue: Arc<RwLock<Vec<Task>>>,
    worker_pool: Arc<RwLock<HashMap<WorkerId, WorkerInfo>>>,
    job_splitter: JobSplitter,
    result_assembler: ResultAssembler,
    /// Payment client for encrypted privacy payments
    payment_client: Option<Arc<PaymentRouterClient>>,
    /// Privacy payment configuration
    privacy_config: PrivacyPaymentConfig,
}

/// Internal job state
#[derive(Debug)]
pub struct JobState {
    pub job_id: JobId,
    pub request: JobRequest,
    pub tasks: Vec<Task>,
    pub status: JobStatus,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub estimated_completion: Option<chrono::DateTime<chrono::Utc>>,
}

/// Worker information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerInfo {
    pub worker_id: WorkerId,
    pub node_id: crate::types::NodeId,
    pub capabilities: WorkerCapabilities,
    pub current_load: f32,
    pub reputation: f32,
    pub last_seen: chrono::DateTime<chrono::Utc>,
    /// Starknet wallet address for stake verification and payments
    pub wallet_address: Option<String>,
    /// ElGamal public key for encrypted privacy payments
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privacy_public_key: Option<ECPoint>,
}

impl JobCoordinator {
    /// Create a new JobCoordinator (sync, no privacy payments)
    pub fn new(
        database: Arc<Database>,
        job_manager: Arc<JobManagerContract>,
        blockchain_config: BlockchainConfig,
    ) -> Self {
        Self {
            database,
            job_manager,
            blockchain_config,
            active_jobs: Arc::new(RwLock::new(HashMap::new())),
            task_queue: Arc::new(RwLock::new(Vec::new())),
            worker_pool: Arc::new(RwLock::new(HashMap::new())),
            job_splitter: JobSplitter::new(),
            result_assembler: ResultAssembler::new(),
            payment_client: None,
            privacy_config: PrivacyPaymentConfig::default(),
        }
    }

    /// Create a new JobCoordinator with privacy payment support (async)
    pub async fn with_privacy_config(
        database: Arc<Database>,
        job_manager: Arc<JobManagerContract>,
        blockchain_config: BlockchainConfig,
        privacy_config: PrivacyPaymentConfig,
    ) -> Result<Self> {
        // Initialize payment client if privacy payments are enabled
        let payment_client = if privacy_config.enabled {
            match Self::create_payment_client(&privacy_config).await {
                Ok(client) => {
                    info!("Privacy payment client initialized");
                    Some(Arc::new(client))
                }
                Err(e) => {
                    warn!("Failed to initialize privacy payment client: {}", e);
                    None
                }
            }
        } else {
            None
        };

        Ok(Self {
            database,
            job_manager,
            blockchain_config,
            active_jobs: Arc::new(RwLock::new(HashMap::new())),
            task_queue: Arc::new(RwLock::new(Vec::new())),
            worker_pool: Arc::new(RwLock::new(HashMap::new())),
            job_splitter: JobSplitter::new(),
            result_assembler: ResultAssembler::new(),
            payment_client,
            privacy_config,
        })
    }

    /// Create a payment router client from config (async)
    async fn create_payment_client(config: &PrivacyPaymentConfig) -> Result<PaymentRouterClient> {
        let rpc_url = config.starknet_rpc_url.as_ref()
            .ok_or_else(|| anyhow!("Starknet RPC URL required for privacy payments"))?;

        let private_key = config.starknet_private_key.as_ref()
            .ok_or_else(|| anyhow!("Starknet private key required for privacy payments"))?;

        let account_address_str = config.starknet_account_address.as_ref()
            .ok_or_else(|| anyhow!("Starknet account address required for privacy payments"))?;

        let account_address = FieldElement::from_hex_be(account_address_str)
            .map_err(|e| anyhow!("Invalid account address: {}", e))?;

        // Get payment router address from config, with default for Sepolia
        let contract_address_str = config.payment_router_address.as_ref()
            .map(|s| s.as_str())
            .unwrap_or("0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d");

        let contract_address = FieldElement::from_hex_be(contract_address_str)
            .map_err(|e| anyhow!("Invalid payment router contract address: {}", e))?;

        PaymentRouterClient::new(rpc_url, contract_address, private_key, account_address).await
    }

    /// Check if privacy payments are enabled
    pub fn is_privacy_payments_enabled(&self) -> bool {
        self.privacy_config.enabled && self.payment_client.is_some()
    }

    // =========================================================================
    // Payment Calculation
    // =========================================================================

    /// Calculate payment amount for a single task
    ///
    /// Pricing is based on:
    /// - Base rate per task (from config)
    /// - Job type complexity multiplier
    /// - GPU usage bonus
    /// - Execution time
    fn calculate_task_payment(&self, task: &Task, job_type: &JobType) -> u128 {
        let base_rate = self.privacy_config.base_payment_rate;
        if base_rate == 0 {
            return 0; // Payments disabled
        }

        // Complexity multiplier based on job type
        let complexity_multiplier: u128 = match job_type {
            JobType::AIInference { .. } => 1,
            JobType::ComputerVision { .. } => 2,
            JobType::VideoProcessing { .. } => 2,
            JobType::Render3D { .. } => 3,
            JobType::NLP { .. } => 2,
            JobType::AudioProcessing { .. } => 2,
            JobType::TimeSeriesAnalysis { .. } => 1,
            JobType::MultimodalAI { .. } => 3,
            JobType::ReinforcementLearning { .. } => 5,
            JobType::SpecializedAI { .. } => 3,
            JobType::ZKProof { .. } => 4,
            JobType::Custom { .. } => 1,
            JobType::DataPipeline { .. } => 2,
            JobType::ConfidentialVM { .. } => 4,
        };

        // GPU bonus (50% extra if GPU required)
        let gpu_bonus: u128 = if task.gpu_required { 50 } else { 0 };

        // Execution time bonus (1 unit per second estimated)
        let time_bonus = task.estimated_duration as u128;

        // Memory usage bonus (1 unit per 100MB)
        let memory_bonus = task.estimated_memory as u128 / 100;

        // Calculate total
        let base = base_rate * complexity_multiplier;
        let bonuses = (base * gpu_bonus) / 100 + time_bonus + memory_bonus;

        base + bonuses
    }

    /// Create encrypted payment for a worker
    ///
    /// Encrypts the payment amount to the worker's ElGamal public key and
    /// submits it to the PaymentRouter contract on-chain. Supports multi-asset
    /// payments where the asset type is specified.
    async fn create_encrypted_payment(
        &self,
        worker_id: &WorkerId,
        job_id: &JobId,
        amount: u128,
        asset_id: AssetId,
        proof: Option<&CompressedProof>,
    ) -> Result<FieldElement> {
        let payment_client = self.payment_client.as_ref()
            .ok_or_else(|| anyhow!("Payment client not configured"))?;

        // Get worker info from pool
        let workers = self.worker_pool.read().await;
        let worker_info = workers.get(worker_id)
            .ok_or_else(|| anyhow!("Worker not found: {}", worker_id))?;

        let wallet_address = worker_info.wallet_address.as_ref()
            .ok_or_else(|| anyhow!("Worker {} has no wallet address", worker_id))?;

        let public_key = worker_info.privacy_public_key.as_ref()
            .ok_or_else(|| anyhow!("Worker {} has no privacy public key - cannot create encrypted payment", worker_id))?;

        // Convert job_id to u128 for on-chain
        let job_id_u128 = job_id.0.as_u128();

        // Submit encrypted payment with asset specification
        let result = if let Some(proof) = proof {
            // Payment gated by proof verification
            payment_client.submit_encrypted_payment_with_proof_for_asset(
                wallet_address,
                public_key,
                job_id_u128,
                amount,
                asset_id,
                proof,
            ).await?
        } else {
            // Simple encrypted payment without proof (for testing/fallback)
            // Create a minimal placeholder proof
            warn!("Creating encrypted {} payment without proof for job {} - this should only happen in testing",
                  asset_id.name(), job_id);
            let placeholder_proof = CompressedProof {
                data: vec![0u8; 32],
                original_size: 32,
                algorithm: crate::obelysk::proof_compression::CompressionAlgorithm::None,
                proof_hash: [0u8; 32],
                compressed_hash: *blake3::hash(&[0u8; 32]).as_bytes(),
                compression_ratio: 1.0,
            };
            payment_client.submit_encrypted_payment_with_proof_for_asset(
                wallet_address,
                public_key,
                job_id_u128,
                amount,
                asset_id,
                &placeholder_proof,
            ).await?
        };

        info!(
            "Created encrypted {} payment for worker {}: job={}, amount={}, tx={:?}",
            asset_id.name(), worker_id, job_id, amount, result.tx_hash
        );

        Ok(result.tx_hash)
    }

    /// Process payments for all workers after job completion
    ///
    /// Supports multi-asset payments - extracts the payment token from job
    /// request or falls back to the configured default.
    async fn process_job_payments(&self, job_id: &JobId) -> Result<()> {
        if !self.is_privacy_payments_enabled() {
            debug!("Privacy payments disabled, skipping payment processing for job {}", job_id);
            return Ok(());
        }

        // Get job state to determine payment asset
        let asset_id = {
            let jobs = self.active_jobs.read().await;
            jobs.get(job_id)
                .and_then(|state| self.extract_payment_asset(&state.request))
                .unwrap_or(self.privacy_config.default_payment_asset)
        };

        // Calculate payments for each worker (amount depends on asset)
        let worker_payments = self.calculate_worker_payments_for_asset(job_id, asset_id).await?;

        if worker_payments.is_empty() {
            debug!("No worker payments to process for job {}", job_id);
            return Ok(());
        }

        info!("Processing {} worker {} payments for job {}",
              worker_payments.len(), asset_id.name(), job_id);

        // Create encrypted payment for each worker
        for (worker_id, amount) in worker_payments {
            if amount == 0 {
                continue;
            }

            // Phase 6: Aggregate zkML proofs from task results for payment verification.
            // This will enable proof-gated payments where workers must prove computation.
            // For now, we pass None for the proof (payments are trust-based).
            match self.create_encrypted_payment(&worker_id, job_id, amount, asset_id, None).await {
                Ok(tx_hash) => {
                    info!("Payment created for worker {}: {} {} tokens, tx={:?}",
                          worker_id, amount, asset_id.name(), tx_hash);
                }
                Err(e) => {
                    warn!("Failed to create {} payment for worker {} on job {}: {}",
                          asset_id.name(), worker_id, job_id, e);
                    // Continue with other workers, don't fail the entire job
                }
            }
        }

        Ok(())
    }

    /// Extract payment asset from job request
    ///
    /// Looks for a "payment_token" field in the job request, falling back to None
    /// if not specified. Caller should use default_payment_asset if None.
    fn extract_payment_asset(&self, request: &JobRequest) -> Option<AssetId> {
        // Check for payment_token in AIInference parameters
        if let JobType::AIInference { parameters, .. } = &request.job_type {
            if let Some(token) = parameters.get("payment_token") {
                if let Some(token_str) = token.as_str() {
                    return Some(Self::parse_asset_id_from_string(token_str));
                }
            }
        }
        // Could add support for other job types here
        None
    }

    /// Parse asset ID from string
    fn parse_asset_id_from_string(s: &str) -> AssetId {
        match s.to_uppercase().as_str() {
            "SAGE" | "0" => AssetId::SAGE,
            "USDC" | "1" => AssetId::USDC,
            "STRK" | "2" => AssetId::STRK,
            "BTC" | "WBTC" | "3" => AssetId::BTC,
            "ETH" | "4" => AssetId::ETH,
            _ => {
                warn!("Unknown payment token '{}', defaulting to SAGE", s);
                AssetId::SAGE
            }
        }
    }

    /// Calculate payments for workers on a job, using asset-specific rates
    async fn calculate_worker_payments_for_asset(
        &self,
        job_id: &JobId,
        asset_id: AssetId,
    ) -> Result<HashMap<WorkerId, u128>> {
        // Get base rate for this asset
        let base_rate = self.privacy_config.base_payment_rates
            .get(&asset_id)
            .copied()
            .unwrap_or(self.privacy_config.base_payment_rate);

        // Delegate to existing calculation with asset-specific rate
        self.calculate_worker_payments_with_rate(job_id, base_rate).await
    }

    /// Calculate payments using a specific rate
    ///
    /// Payment is calculated as: base_rate × task_complexity
    /// where complexity is derived from estimated duration and GPU requirements.
    async fn calculate_worker_payments_with_rate(
        &self,
        job_id: &JobId,
        base_rate: u128,
    ) -> Result<HashMap<WorkerId, u128>> {
        let mut payments = HashMap::new();

        // Get job state
        let jobs = self.active_jobs.read().await;
        let job_state = jobs.get(job_id)
            .ok_or_else(|| anyhow!("Job not found: {}", job_id))?;

        // Calculate payment per task based on complexity and base rate
        for task in &job_state.tasks {
            if let Some(ref worker_id) = task.assigned_worker {
                // Calculate complexity based on estimated duration and GPU requirement
                // Base: 1x for simple tasks, more for longer/GPU tasks
                let duration_factor = (task.estimated_duration / 60).max(1) as u128; // Per minute
                let gpu_factor = if task.gpu_required { 2 } else { 1 };
                let complexity = duration_factor * gpu_factor;

                let task_payment = base_rate * complexity;
                *payments.entry(worker_id.clone()).or_insert(0u128) += task_payment;
            }
        }

        Ok(payments)
    }

    /// Parse private key from config
    fn parse_private_key(&self) -> Result<FieldElement> {
        let key_str = &self.blockchain_config.signer_private_key;
        let key_str = if key_str.starts_with("0x") {
            &key_str[2..]
        } else {
            key_str
        };
        FieldElement::from_hex_be(key_str)
            .map_err(|e| anyhow!("Failed to parse private key: {}", e))
    }

    /// Parse account address from config
    fn parse_account_address(&self) -> Result<FieldElement> {
        let addr_str = &self.blockchain_config.signer_account_address;
        let addr_str = if addr_str.starts_with("0x") {
            &addr_str[2..]
        } else {
            addr_str
        };
        FieldElement::from_hex_be(addr_str)
            .map_err(|e| anyhow!("Failed to parse account address: {}", e))
    }

    /// Submit a new job for processing
    pub async fn submit_job(&self, request: JobRequest) -> Result<JobId> {
        let job_id = JobId::new();
        info!("Submitting job {} of type {:?}", job_id, request.job_type);

        // Analyze job and create parallelization strategy
        let strategy = self.job_splitter.analyze_job(&request.job_type).await?;
        debug!("Job {} parallelization strategy: {:?}", job_id, strategy);

        // Split job into tasks
        let tasks = self.job_splitter.split_job(job_id, &request.job_type, &strategy).await?;
        info!("Job {} split into {} tasks", job_id, tasks.len());

        // Create job state
        let job_state = JobState {
            job_id,
            request: request.clone(),
            tasks: tasks.clone(),
            status: JobStatus::Queued,
            created_at: chrono::Utc::now(),
            estimated_completion: None,
        };

        // Store job in database
        self.database.store_job(&job_state).await?;

        // Add to active jobs
        self.active_jobs.write().await.insert(job_id, job_state);

        // Add tasks to queue
        let mut task_queue = self.task_queue.write().await;
        task_queue.extend(tasks);

        // Register job on blockchain
        let private_key = self.parse_private_key()?;
        let account_address = self.parse_account_address()?;
        self.job_manager.register_job(job_id, &request, private_key, account_address).await?;

        Ok(job_id)
    }

    /// Get job status
    pub async fn get_job_status(&self, job_id: JobId) -> Result<JobResult> {
        let jobs = self.active_jobs.read().await;
        let job_state = jobs.get(&job_id)
            .ok_or_else(|| anyhow!("Job {} not found", job_id))?;

        let completed_tasks = job_state.tasks.iter()
            .filter(|t| t.status == TaskStatus::Completed)
            .count() as u32;

        let total_tasks = job_state.tasks.len() as u32;

        // Calculate execution time from first task start to last task completion
        let (execution_time, proof_time_ms) = self.calculate_execution_time(&job_state.tasks);

        // Calculate total cost based on completed task estimates
        let total_cost = self.calculate_total_cost(&job_state.tasks, &job_state.request.job_type);

        // Aggregate output files from completed tasks
        let output_files = self.aggregate_output_files(&job_state.tasks).await;

        // Aggregate proof data from completed tasks
        let (proof_hash, proof_attestation, proof_size) = self.aggregate_proof_data(&job_state.tasks);

        // Determine if there were any errors
        let error_message = job_state.tasks.iter()
            .find(|t| t.status == TaskStatus::Failed)
            .map(|_| "One or more tasks failed during execution".to_string());

        Ok(JobResult {
            job_id,
            status: job_state.status.clone(),
            completed_tasks,
            total_tasks,
            output_files,
            execution_time,
            total_cost,
            error_message,
            proof_hash,
            proof_attestation,
            proof_commitment: None, // Will be set during on-chain submission
            compressed_proof: None, // Will be set during proof compression
            proof_size_bytes: proof_size,
            proof_time_ms,
        })
    }

    /// Calculate execution time from tasks
    fn calculate_execution_time(&self, tasks: &[Task]) -> (u64, Option<u64>) {
        let started_tasks: Vec<_> = tasks.iter()
            .filter_map(|t| t.started_at)
            .collect();

        let completed_tasks: Vec<_> = tasks.iter()
            .filter_map(|t| t.completed_at)
            .collect();

        if started_tasks.is_empty() || completed_tasks.is_empty() {
            return (0, None);
        }

        // Find earliest start and latest completion
        let earliest_start = started_tasks.iter().min().unwrap();
        let latest_completion = completed_tasks.iter().max().unwrap();

        let execution_time = (*latest_completion - *earliest_start).num_seconds().max(0) as u64;

        // Calculate total proof generation time (sum of all task durations)
        let total_proof_time: i64 = tasks.iter()
            .filter(|t| t.status == TaskStatus::Completed)
            .filter_map(|t| {
                if let (Some(start), Some(end)) = (t.started_at, t.completed_at) {
                    Some((end - start).num_milliseconds())
                } else {
                    None
                }
            })
            .sum();

        (execution_time, Some(total_proof_time.max(0) as u64))
    }

    /// Calculate total cost for completed tasks
    fn calculate_total_cost(&self, tasks: &[Task], job_type: &JobType) -> u64 {
        let mut total: u128 = 0;

        for task in tasks {
            if task.status == TaskStatus::Completed {
                total += self.calculate_task_payment(task, job_type);
            }
        }

        // Convert from u128 wei to u64 (truncate if necessary)
        (total / 1_000_000_000_000) as u64 // Convert to micro-SAGE
    }

    /// Aggregate output files from completed tasks
    async fn aggregate_output_files(&self, tasks: &[Task]) -> Vec<String> {
        let mut output_files = Vec::new();

        for task in tasks {
            if task.status == TaskStatus::Completed {
                // Check if task has output files in its parameters
                if let Some(files) = task.input_data.parameters.get("output_files") {
                    if let Some(arr) = files.as_array() {
                        for file in arr {
                            if let Some(f) = file.as_str() {
                                output_files.push(f.to_string());
                            }
                        }
                    }
                }

                // Also check for result file path based on chunk info
                if let Some(ref chunk_info) = task.input_data.chunk_info {
                    output_files.push(format!(
                        "result_chunk_{}_of_{}.dat",
                        chunk_info.chunk_id,
                        chunk_info.total_chunks
                    ));
                }
            }
        }

        output_files
    }

    /// Aggregate proof data from completed tasks
    fn aggregate_proof_data(&self, tasks: &[Task]) -> (Option<[u8; 32]>, Option<[u8; 32]>, Option<usize>) {
        let completed_tasks: Vec<_> = tasks.iter()
            .filter(|t| t.status == TaskStatus::Completed)
            .collect();

        if completed_tasks.is_empty() {
            return (None, None, None);
        }

        // Create aggregate proof hash by hashing all task IDs together
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        let mut total_size: usize = 0;

        for task in &completed_tasks {
            hasher.update(task.id.to_string().as_bytes());
            // Estimate proof size based on task type and duration
            total_size += (task.estimated_duration as usize * 128).min(32768); // ~128 bytes per second, max 32KB per task
        }

        let hash_result = hasher.finalize();
        let mut proof_hash = [0u8; 32];
        proof_hash.copy_from_slice(&hash_result);

        // Create attestation hash (simplified - in production this would come from TEE)
        let mut attestation_hasher = Sha256::new();
        attestation_hasher.update(&proof_hash);
        attestation_hasher.update(b"bitsage_attestation_v1");
        let attestation_result = attestation_hasher.finalize();
        let mut attestation = [0u8; 32];
        attestation.copy_from_slice(&attestation_result);

        (Some(proof_hash), Some(attestation), Some(total_size))
    }

    /// Register a new worker
    pub async fn register_worker(&self, worker_info: WorkerInfo) -> Result<()> {
        info!("Registering worker {}", worker_info.worker_id);
        
        self.worker_pool.write().await.insert(
            worker_info.worker_id,
            worker_info.clone()
        );

        self.database.store_worker(&worker_info).await?;
        Ok(())
    }

    /// Assign tasks to available workers
    pub async fn schedule_tasks(&self) -> Result<()> {
        let mut task_queue = self.task_queue.write().await;
        let worker_pool = self.worker_pool.read().await;

        // Find available workers
        let available_workers: Vec<_> = worker_pool.values()
            .filter(|w| w.current_load < 0.8) // Not overloaded
            .collect();

        if available_workers.is_empty() {
            return Ok(());
        }

        // Assign tasks to workers
        let mut assigned_tasks = Vec::new();
        for (i, task) in task_queue.iter_mut().enumerate() {
            if task.status != TaskStatus::Pending {
                continue;
            }

            // Find best worker for this task
            if let Some(worker) = self.find_best_worker(&available_workers, task) {
                task.assigned_worker = Some(worker.worker_id);
                task.status = TaskStatus::Assigned;
                assigned_tasks.push(i);
                
                info!("Assigned task {} to worker {}", task.id, worker.worker_id);
            }
        }

        // Remove assigned tasks from queue
        for &i in assigned_tasks.iter().rev() {
            task_queue.remove(i);
        }

        Ok(())
    }

    /// Find the best worker for a given task
    fn find_best_worker<'a>(&self, workers: &[&'a WorkerInfo], task: &Task) -> Option<&'a WorkerInfo> {
        workers.iter()
            .filter(|w| self.worker_can_handle_task(w, task))
            .min_by(|a, b| a.current_load.partial_cmp(&b.current_load)
                .unwrap_or(std::cmp::Ordering::Equal))
            .copied()
    }

    /// Check if a worker can handle a specific task
    fn worker_can_handle_task(&self, worker: &WorkerInfo, task: &Task) -> bool {
        // Check GPU requirement
        if task.gpu_required && worker.capabilities.gpu_memory == 0 {
            return false;
        }

        // Check memory requirement
        if task.estimated_memory > worker.capabilities.ram_gb as u64 * 1024 {
            return false;
        }

        // Check job type support
        let job_type_str = match &task.task_type {
            JobType::Render3D { .. } => "render3d",
            JobType::VideoProcessing { .. } => "video",
            JobType::AIInference { .. } => "ai",
            JobType::ComputerVision { .. } => "computer_vision",
            JobType::NLP { .. } => "nlp",
            JobType::AudioProcessing { .. } => "audio",
            JobType::TimeSeriesAnalysis { .. } => "time_series",
            JobType::MultimodalAI { .. } => "multimodal",
            JobType::ReinforcementLearning { .. } => "reinforcement_learning",
            JobType::SpecializedAI { domain, .. } => {
                match domain {
                    AIDomain::Medical => "medical_ai",
                    AIDomain::Scientific => "scientific_ai",
                    AIDomain::Robotics => "robotics_ai",
                    AIDomain::AutonomousSystems => "autonomous_ai",
                    AIDomain::ClimateModeling => "climate_ai",
                    AIDomain::Bioinformatics => "bioinformatics_ai",
                    AIDomain::DrugDiscovery => "drug_discovery_ai",
                    AIDomain::MaterialsScience => "materials_ai",
                    AIDomain::Astronomy => "astronomy_ai",
                    AIDomain::Finance => "finance_ai",
                    AIDomain::Cybersecurity => "cybersecurity_ai",
                    AIDomain::Custom(name) => return worker.capabilities.supported_job_types.contains(&format!("custom_{}", name)),
                }
            }
            JobType::ZKProof { .. } => "zkproof",
            JobType::Custom { .. } => "custom",
            JobType::DataPipeline { .. } => "data_pipeline",
            JobType::ConfidentialVM { .. } => "confidential_vm",
        };

        worker.capabilities.supported_job_types.contains(&job_type_str.to_string())
    }

    /// Handle task completion
    pub async fn handle_task_completion(
        &self,
        task_id: TaskId,
        result: TaskResult,
    ) -> Result<()> {
        info!("Task {} completed with status: {:?}", task_id, result.status);

        // Update task status in database
        let is_completed = result.status == TaskStatus::Completed;
        let status_input = crate::storage::models::UpdateTaskStatusInput {
            status: result.status.into(),
            worker_id: None,
            started_at: None,
            completed_at: if is_completed { Some(chrono::Utc::now()) } else { None },
            output_data: if !result.output_files.is_empty() { Some(serde_json::to_value(&result.output_files)?) } else { None },
            cpu_usage_percent: None,
            memory_usage_mb: Some(result.resource_usage.memory_peak as i32),
            gpu_usage_percent: None,
            processing_time_ms: Some(result.execution_time as i64),
            error_message: result.error_message.clone(),
        };
        self.database.update_task_status(&task_id.to_string(), status_input).await?;

        // Check if job is complete
        if let Some(job_id_str) = self.database.get_job_id_for_task(&task_id.to_string()).await? {
            if let Ok(job_id) = job_id_str.parse::<JobId>() {
                self.check_job_completion(job_id).await?;
            }
        }

        Ok(())
    }

    /// Check if a job is complete and handle result assembly
    async fn check_job_completion(&self, job_id: JobId) -> Result<()> {
        let is_complete = {
            let mut jobs = self.active_jobs.write().await;
            if let Some(job_state) = jobs.get_mut(&job_id) {
                let completed_tasks = job_state.tasks.iter()
                    .filter(|t| t.status == TaskStatus::Completed)
                    .count();

                if completed_tasks == job_state.tasks.len() {
                    job_state.status = JobStatus::Completed;

                    // Assemble final result
                    let _final_result = self.result_assembler
                        .assemble_job_result(job_id, &job_state.tasks)
                        .await?;

                    // Create job result
                    let job_result = JobResult {
                        job_id,
                        status: JobStatus::Completed,
                        completed_tasks: completed_tasks as u32,
                        total_tasks: job_state.tasks.len() as u32,
                        output_files: Vec::new(),
                        execution_time: 0,
                        total_cost: 0,
                        error_message: None,
                        proof_hash: None, // Phase 6: Aggregate Stwo proofs from all tasks
                        proof_attestation: None,
                        proof_commitment: None,
                        compressed_proof: None,
                        proof_size_bytes: None,
                        proof_time_ms: None,
                    };

                    // Notify blockchain
                    let private_key = self.parse_private_key()?;
                    let account_address = self.parse_account_address()?;
                    self.job_manager.complete_job(job_id, &job_result, private_key, account_address).await?;

                    true
                } else {
                    false
                }
            } else {
                false
            }
        };

        // Process encrypted payments after job completion (outside the lock)
        if is_complete {
            if let Err(e) = self.process_job_payments(&job_id).await {
                warn!("Failed to process payments for job {}: {}", job_id, e);
                // Don't fail the job completion just because payments failed
            }
        }

        Ok(())
    }
}

/// Task execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResult {
    pub task_id: TaskId,
    pub status: TaskStatus,
    pub output_files: Vec<String>,
    pub execution_time: u64,
    pub error_message: Option<String>,
    pub resource_usage: ResourceUsage,
}

/// Resource usage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub cpu_time: u64,
    pub memory_peak: u64,
    pub gpu_time: Option<u64>,
    pub network_io: u64,
    pub disk_io: u64,
}

/// Estimate task resources based on job type and chunk size
/// Returns: (duration_secs, memory_mb, gpu_required)
fn estimate_task_resources(job_type: &JobType, chunk_size: u32) -> (u64, u64, bool) {
    match job_type {
        JobType::AIInference { model_type, .. } => {
            let model_lower = model_type.to_lowercase();
            let (base_duration, base_memory) = if model_lower.contains("70b") {
                (120, 65536) // 2 min, 64GB
            } else if model_lower.contains("13b") {
                (60, 16384) // 1 min, 16GB
            } else if model_lower.contains("7b") {
                (30, 8192) // 30s, 8GB
            } else if model_lower.contains("bert") || model_lower.contains("roberta") {
                (10, 2048) // 10s, 2GB
            } else if model_lower.contains("diffusion") || model_lower.contains("dall") {
                (45, 12288) // 45s, 12GB
            } else {
                (30, 4096) // Default: 30s, 4GB
            };
            let duration = base_duration + (chunk_size as u64 * 2);
            (duration, base_memory, true)
        }

        JobType::ComputerVision { task_type, .. } => {
            let (base_duration, base_memory) = match task_type {
                CVTaskType::ImageGeneration => (30, 8192),
                CVTaskType::StyleTransfer => (15, 4096),
                CVTaskType::ObjectDetection => (5, 2048),
                CVTaskType::ImageSegmentation => (10, 4096),
                CVTaskType::SuperResolution => (20, 6144),
                _ => (10, 4096),
            };
            let duration = base_duration + (chunk_size as u64);
            (duration, base_memory, true)
        }

        JobType::NLP { task_type, max_tokens, .. } => {
            let (base_duration, base_memory) = match task_type {
                NLPTaskType::TextGeneration => (30, 8192),
                NLPTaskType::TextSummarization => (15, 4096),
                NLPTaskType::Translation => (10, 4096),
                NLPTaskType::SentimentAnalysis => (5, 2048),
                NLPTaskType::CodeGeneration => (60, 12288),
                _ => (15, 4096),
            };
            let token_mult = (*max_tokens as f64 / 1000.0).max(1.0);
            let duration = (base_duration as f64 * token_mult) as u64;
            (duration, base_memory, true)
        }

        JobType::VideoProcessing { resolution, frame_rate, .. } => {
            let pixels = (resolution.0 as u64) * (resolution.1 as u64);
            let complexity = (pixels as f64 / 2073600.0).max(1.0);
            let base_duration = (chunk_size as f64 / *frame_rate as f64 * 2.0 * complexity) as u64;
            let memory = 4096 + (pixels / 1000);
            (base_duration.max(10), memory, true)
        }

        JobType::Render3D { output_resolution, quality_preset, .. } => {
            let pixels = (output_resolution.0 as u64) * (output_resolution.1 as u64);
            let quality_mult = match quality_preset.to_lowercase().as_str() {
                "low" => 0.5,
                "medium" => 1.0,
                "high" => 2.5,
                "ultra" => 5.0,
                _ => 1.0,
            };
            let duration = ((pixels as f64 / 2073600.0) * 60.0 * quality_mult * chunk_size as f64) as u64;
            let memory = 8192 + (pixels / 256);
            (duration.max(30), memory, true)
        }

        JobType::AudioProcessing { task_type, .. } => {
            let (base_duration, base_memory) = match task_type {
                AudioTaskType::SpeechToText => (30, 2048),
                AudioTaskType::TextToSpeech => (15, 2048),
                AudioTaskType::MusicGeneration => (120, 8192),
                AudioTaskType::VoiceConversion => (45, 4096),
                _ => (20, 2048),
            };
            (base_duration, base_memory, true)
        }

        JobType::ZKProof { proof_system, circuit_type, .. } => {
            let base_duration = match proof_system.to_lowercase().as_str() {
                "stwo" => 120,
                "stark" => 180,
                "snark" | "groth16" => 90,
                "plonk" => 100,
                _ => 150,
            };
            let circuit_mult = if circuit_type.contains("large") { 3.0 }
                else if circuit_type.contains("medium") { 2.0 }
                else { 1.0 };
            let duration = (base_duration as f64 * circuit_mult) as u64;
            (duration, 16384, true)
        }

        JobType::TimeSeriesAnalysis { forecast_horizon, .. } => {
            let duration = 30 + (*forecast_horizon as u64 / 10);
            (duration, 2048, false)
        }

        JobType::ReinforcementLearning { training_steps, .. } => {
            let duration = (*training_steps / 100).max(60) as u64;
            (duration, 8192, true)
        }

        JobType::MultimodalAI { task_type, .. } => {
            let duration = match task_type {
                MultimodalTaskType::VideoUnderstanding => 180,
                MultimodalTaskType::ImageCaptioning => 30,
                MultimodalTaskType::VisualQuestionAnswering => 45,
                _ => 60,
            };
            (duration, 12288, true)
        }

        JobType::DataPipeline { tee_required, .. } => {
            let duration = if *tee_required { 120 } else { 60 };
            (duration, 4096, false)
        }

        JobType::ConfidentialVM { memory_mb, .. } => {
            ((*memory_mb as u64 / 100).max(60), *memory_mb as u64, false)
        }

        JobType::SpecializedAI { computational_requirements, .. } => {
            let duration = (computational_requirements.estimated_runtime_minutes * 60) as u64;
            let memory = (computational_requirements.min_ram_gb * 1024) as u64;
            let gpu = computational_requirements.min_gpu_memory_gb > 0;
            (duration.max(30), memory.max(2048), gpu)
        }

        JobType::Custom { parallelizable, .. } => {
            let duration = if *parallelizable { 60 } else { 120 };
            (duration, 2048, false)
        }
    }
}

/// Job splitting logic
#[derive(Debug, Clone)]
pub struct JobSplitter;

impl JobSplitter {
    pub fn new() -> Self {
        Self
    }

    /// Analyze a job and determine the best parallelization strategy
    pub async fn analyze_job(&self, job_type: &JobType) -> Result<ParallelizationStrategy> {
        match job_type {
            JobType::Render3D { frames, output_resolution, .. } => {
                if let Some(frame_count) = frames {
                    Ok(ParallelizationStrategy::FrameBased {
                        total_frames: *frame_count,
                        frames_per_chunk: self.calculate_optimal_frames_per_chunk(*frame_count),
                    })
                } else {
                    Ok(ParallelizationStrategy::TileBased {
                        image_width: output_resolution.0,
                        image_height: output_resolution.1,
                        tile_size: self.calculate_optimal_tile_size(*output_resolution),
                    })
                }
            }
            JobType::VideoProcessing { duration, frame_rate, .. } => {
                let total_frames = (*duration * *frame_rate) as u32;
                Ok(ParallelizationStrategy::FrameBased {
                    total_frames,
                    frames_per_chunk: self.calculate_optimal_frames_per_chunk(total_frames),
                })
            }
            JobType::AIInference { batch_size, .. } => {
                Ok(ParallelizationStrategy::BatchBased {
                    total_items: *batch_size,
                    batch_size: self.calculate_optimal_batch_size(*batch_size),
                })
            }
            JobType::ComputerVision { batch_size, input_images, task_type, .. } => {
                let total_items = std::cmp::max(*batch_size, input_images.len() as u32);
                match task_type {
                    CVTaskType::ImageGeneration | CVTaskType::StyleTransfer => {
                        // Image generation tasks are typically sequential or small batch
                        Ok(ParallelizationStrategy::Sequential)
                    }
                    _ => {
                        // Most CV tasks can be parallelized by batch
                        Ok(ParallelizationStrategy::BatchBased {
                            total_items,
                            batch_size: self.calculate_optimal_batch_size(total_items),
                        })
                    }
                }
            }
            JobType::NLP { input_text, task_type, .. } => {
                let total_items = input_text.len() as u32;
                match task_type {
                    NLPTaskType::TextGeneration | NLPTaskType::ConversationalAI => {
                        // Text generation is typically sequential
                        Ok(ParallelizationStrategy::Sequential)
                    }
                    _ => {
                        // Most NLP tasks can be parallelized by batch
                        Ok(ParallelizationStrategy::BatchBased {
                            total_items,
                            batch_size: self.calculate_optimal_batch_size(total_items),
                        })
                    }
                }
            }
            JobType::AudioProcessing { input_audio, task_type, .. } => {
                let total_items = input_audio.len() as u32;
                match task_type {
                    AudioTaskType::MusicGeneration | AudioTaskType::VoiceConversion => {
                        // Audio generation tasks are typically sequential
                        Ok(ParallelizationStrategy::Sequential)
                    }
                    _ => {
                        // Most audio tasks can be parallelized by batch
                        Ok(ParallelizationStrategy::BatchBased {
                            total_items,
                            batch_size: self.calculate_optimal_batch_size(total_items),
                        })
                    }
                }
            }
            JobType::TimeSeriesAnalysis { input_data, task_type, .. } => {
                let data_points = input_data.len() as u32;
                match task_type {
                    TimeSeriesTaskType::Forecasting | TimeSeriesTaskType::AnomalyDetection => {
                        // Time series analysis can be parallelized by splitting the data
                        if data_points > 1000 {
                            Ok(ParallelizationStrategy::BatchBased {
                                total_items: data_points / 100, // Split into chunks of 100 points
                                batch_size: self.calculate_optimal_batch_size(data_points / 100),
                            })
                        } else {
                            Ok(ParallelizationStrategy::Sequential)
                        }
                    }
                    _ => Ok(ParallelizationStrategy::Sequential)
                }
            }
            JobType::MultimodalAI { task_type, .. } => {
                match task_type {
                    MultimodalTaskType::ImageCaptioning | MultimodalTaskType::VisualQuestionAnswering => {
                        // Simple multimodal tasks can be batched
                        Ok(ParallelizationStrategy::BatchBased {
                            total_items: 1,
                            batch_size: 1,
                        })
                    }
                    _ => {
                        // Complex multimodal tasks are typically sequential
                        Ok(ParallelizationStrategy::Sequential)
                    }
                }
            }
            JobType::ReinforcementLearning { task_type, .. } => {
                match task_type {
                    RLTaskType::MultiAgentRL => {
                        // Multi-agent RL can be parallelized across agents
                        Ok(ParallelizationStrategy::BatchBased {
                            total_items: 4, // Default 4 parallel agents
                            batch_size: 1,
                        })
                    }
                    _ => {
                        // Most RL training is sequential
                        Ok(ParallelizationStrategy::Sequential)
                    }
                }
            }
            JobType::SpecializedAI { computational_requirements, domain, .. } => {
                match domain {
                    AIDomain::Medical | AIDomain::Scientific => {
                        // Specialized domains may require sequential processing for accuracy
                        if computational_requirements.requires_specialized_hardware {
                            Ok(ParallelizationStrategy::Sequential)
                        } else {
                            Ok(ParallelizationStrategy::BatchBased {
                                total_items: 1,
                                batch_size: 1,
                            })
                        }
                    }
                    _ => {
                        // Other specialized domains can potentially be parallelized
                        Ok(ParallelizationStrategy::BatchBased {
                            total_items: 1,
                            batch_size: 1,
                        })
                    }
                }
            }
            JobType::ZKProof { .. } => {
                // ZK proofs are typically not parallelizable
                Ok(ParallelizationStrategy::Sequential)
            }
            JobType::Custom { parallelizable, .. } => {
                if *parallelizable {
                    Ok(ParallelizationStrategy::ChunkBased {
                        total_size: 1024 * 1024, // Default 1MB
                        chunk_size: 64 * 1024,   // Default 64KB chunks
                    })
                } else {
                    Ok(ParallelizationStrategy::Sequential)
                }
            }
            JobType::DataPipeline { .. } => {
                // Data pipelines are often parallelizable by data partition, but
                // for MVP we treat them as a single task or batch.
                // In future: ParallelizationStrategy::PartitionBased
                Ok(ParallelizationStrategy::Sequential)
            }
            JobType::ConfidentialVM { .. } => {
                // VMs are single atomic units of compute
                Ok(ParallelizationStrategy::Sequential)
            }
        }
    }

    /// Split a job into individual tasks based on the parallelization strategy
    pub async fn split_job(
        &self,
        job_id: JobId,
        job_type: &JobType,
        strategy: &ParallelizationStrategy,
    ) -> Result<Vec<Task>> {
        match strategy {
            ParallelizationStrategy::FrameBased { total_frames, frames_per_chunk } => {
                self.split_by_frames(job_id, job_type, *total_frames, *frames_per_chunk).await
            }
            ParallelizationStrategy::TileBased { image_width, image_height, tile_size } => {
                self.split_by_tiles(job_id, job_type, *image_width, *image_height, *tile_size).await
            }
            ParallelizationStrategy::ChunkBased { total_size, chunk_size } => {
                self.split_by_chunks(job_id, job_type, *total_size, *chunk_size).await
            }
            ParallelizationStrategy::BatchBased { total_items, batch_size } => {
                self.split_by_batches(job_id, job_type, *total_items, *batch_size).await
            }
            ParallelizationStrategy::Sequential => {
                Ok(vec![self.create_single_task(job_id, job_type).await?])
            }
        }
    }

    /// Split job by video frames
    async fn split_by_frames(
        &self,
        job_id: JobId,
        job_type: &JobType,
        total_frames: u32,
        frames_per_chunk: u32,
    ) -> Result<Vec<Task>> {
        let mut tasks = Vec::new();
        let total_chunks = (total_frames + frames_per_chunk - 1) / frames_per_chunk;

        for chunk_id in 0..total_chunks {
            let start_frame = chunk_id * frames_per_chunk;
            let end_frame = std::cmp::min(start_frame + frames_per_chunk, total_frames);

            let chunk_info = ChunkInfo {
                chunk_id,
                total_chunks,
                start_offset: start_frame as u64,
                end_offset: end_frame as u64,
                frame_range: Some((start_frame, end_frame)),
                tile_coords: None,
            };

            // Calculate better estimates based on job type
            let (est_duration, est_memory, gpu_required) = estimate_task_resources(job_type, frames_per_chunk);

            let task = Task {
                id: TaskId::new(),
                job_id,
                task_type: job_type.clone(),
                input_data: TaskInput {
                    parameters: HashMap::new(),
                    files: Vec::new(),
                    chunk_info: Some(chunk_info),
                },
                dependencies: Vec::new(),
                estimated_duration: est_duration,
                estimated_memory: est_memory,
                gpu_required,
                priority: 5,
                status: TaskStatus::Pending,
                assigned_worker: None,
                created_at: chrono::Utc::now(),
                started_at: None,
                completed_at: None,
            };

            tasks.push(task);
        }

        Ok(tasks)
    }

    /// Split job by image tiles
    async fn split_by_tiles(
        &self,
        job_id: JobId,
        job_type: &JobType,
        image_width: u32,
        image_height: u32,
        tile_size: (u32, u32),
    ) -> Result<Vec<Task>> {
        let mut tasks = Vec::new();
        let tiles_x = (image_width + tile_size.0 - 1) / tile_size.0;
        let tiles_y = (image_height + tile_size.1 - 1) / tile_size.1;
        let total_tiles = tiles_x * tiles_y;

        for tile_y in 0..tiles_y {
            for tile_x in 0..tiles_x {
                let x = tile_x * tile_size.0;
                let y = tile_y * tile_size.1;
                let width = std::cmp::min(tile_size.0, image_width - x);
                let height = std::cmp::min(tile_size.1, image_height - y);

                let chunk_info = ChunkInfo {
                    chunk_id: tile_y * tiles_x + tile_x,
                    total_chunks: total_tiles,
                    start_offset: 0,
                    end_offset: 0,
                    frame_range: None,
                    tile_coords: Some((x, y, width, height)),
                };

                let task = Task {
                    id: TaskId::new(),
                    job_id,
                    task_type: job_type.clone(),
                    input_data: TaskInput {
                        parameters: HashMap::new(),
                        files: Vec::new(),
                        chunk_info: Some(chunk_info),
                    },
                    dependencies: Vec::new(),
                    estimated_duration: 120, // Rendering typically takes longer
                    estimated_memory: 2048,
                    gpu_required: true,
                    priority: 5,
                    status: TaskStatus::Pending,
                    assigned_worker: None,
                    created_at: chrono::Utc::now(),
                    started_at: None,
                    completed_at: None,
                };

                tasks.push(task);
            }
        }

        Ok(tasks)
    }

    /// Split job by data chunks
    async fn split_by_chunks(
        &self,
        job_id: JobId,
        job_type: &JobType,
        total_size: u64,
        chunk_size: u64,
    ) -> Result<Vec<Task>> {
        let mut tasks = Vec::new();
        let total_chunks = (total_size + chunk_size - 1) / chunk_size;

        for chunk_id in 0..total_chunks {
            let start_offset = chunk_id * chunk_size;
            let end_offset = std::cmp::min(start_offset + chunk_size, total_size);

            let chunk_info = ChunkInfo {
                chunk_id: chunk_id as u32,
                total_chunks: total_chunks as u32,
                start_offset,
                end_offset,
                frame_range: None,
                tile_coords: None,
            };

            let task = Task {
                id: TaskId::new(),
                job_id,
                task_type: job_type.clone(),
                input_data: TaskInput {
                    parameters: HashMap::new(),
                    files: Vec::new(),
                    chunk_info: Some(chunk_info),
                },
                dependencies: Vec::new(),
                estimated_duration: 30,
                estimated_memory: 512,
                gpu_required: false,
                priority: 5,
                status: TaskStatus::Pending,
                assigned_worker: None,
                created_at: chrono::Utc::now(),
                started_at: None,
                completed_at: None,
            };

            tasks.push(task);
        }

        Ok(tasks)
    }

    /// Split job by batches
    async fn split_by_batches(
        &self,
        job_id: JobId,
        job_type: &JobType,
        total_items: u32,
        batch_size: u32,
    ) -> Result<Vec<Task>> {
        let mut tasks = Vec::new();
        let total_batches = (total_items + batch_size - 1) / batch_size;

        for batch_id in 0..total_batches {
            let start_item = batch_id * batch_size;
            let end_item = std::cmp::min(start_item + batch_size, total_items);

            let chunk_info = ChunkInfo {
                chunk_id: batch_id,
                total_chunks: total_batches,
                start_offset: start_item as u64,
                end_offset: end_item as u64,
                frame_range: None,
                tile_coords: None,
            };

            let task = Task {
                id: TaskId::new(),
                job_id,
                task_type: job_type.clone(),
                input_data: TaskInput {
                    parameters: HashMap::new(),
                    files: Vec::new(),
                    chunk_info: Some(chunk_info),
                },
                dependencies: Vec::new(),
                estimated_duration: 45,
                estimated_memory: 1024,
                gpu_required: matches!(job_type, JobType::AIInference { .. }),
                priority: 5,
                status: TaskStatus::Pending,
                assigned_worker: None,
                created_at: chrono::Utc::now(),
                started_at: None,
                completed_at: None,
            };

            tasks.push(task);
        }

        Ok(tasks)
    }

    /// Create a single task for non-parallelizable jobs
    async fn create_single_task(&self, job_id: JobId, job_type: &JobType) -> Result<Task> {
        Ok(Task {
            id: TaskId::new(),
            job_id,
            task_type: job_type.clone(),
            input_data: TaskInput {
                parameters: HashMap::new(),
                files: Vec::new(),
                chunk_info: None,
            },
            dependencies: Vec::new(),
            estimated_duration: 300, // 5 minutes default
            estimated_memory: 2048,
            gpu_required: matches!(job_type, JobType::ZKProof { .. }),
            priority: 5,
            status: TaskStatus::Pending,
            assigned_worker: None,
            created_at: chrono::Utc::now(),
            started_at: None,
            completed_at: None,
        })
    }

    /// Calculate optimal frames per chunk based on total frames
    fn calculate_optimal_frames_per_chunk(&self, total_frames: u32) -> u32 {
        match total_frames {
            0..=100 => 10,
            101..=1000 => 25,
            1001..=10000 => 50,
            _ => 100,
        }
    }

    /// Calculate optimal tile size based on image resolution
    fn calculate_optimal_tile_size(&self, resolution: (u32, u32)) -> (u32, u32) {
        let pixels = resolution.0 * resolution.1;
        match pixels {
            0..=1000000 => (256, 256),      // 1MP or less
            1000001..=4000000 => (512, 512), // 1-4MP
            4000001..=16000000 => (1024, 1024), // 4-16MP
            _ => (2048, 2048),              // 16MP+
        }
    }

    /// Calculate optimal batch size for AI inference
    fn calculate_optimal_batch_size(&self, total_items: u32) -> u32 {
        match total_items {
            0..=100 => 10,
            101..=1000 => 50,
            1001..=10000 => 100,
            _ => 200,
        }
    }
}

/// Result assembly logic for combining distributed task outputs
#[derive(Debug, Clone)]
pub struct ResultAssembler {
    /// Temporary storage for intermediate results
    temp_results: Arc<RwLock<HashMap<JobId, Vec<TaskResultChunk>>>>,
}

/// A chunk of task result data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResultChunk {
    pub task_id: TaskId,
    pub chunk_id: u32,
    pub data: Vec<u8>,
    pub metadata: TaskResultMetadata,
}

/// Metadata about a task result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResultMetadata {
    pub job_type: String,
    pub frame_range: Option<(u32, u32)>,
    pub tile_coords: Option<(u32, u32, u32, u32)>,
    pub batch_range: Option<(u32, u32)>,
    pub execution_time_ms: u64,
    pub output_format: Option<String>,
    pub checksum: Option<String>,
}

/// Assembly strategy for different job types
#[derive(Debug, Clone)]
pub enum AssemblyStrategy {
    /// Concatenate chunks in order (videos, audio)
    Sequential,
    /// Stitch tiles together (images, 3D renders)
    TileStitch { width: u32, height: u32, tile_size: (u32, u32) },
    /// Merge batch results (AI inference)
    BatchMerge,
    /// Aggregate results with consensus (ZK proofs)
    Consensus,
    /// Custom assembly with provided function
    Custom(String),
}

impl ResultAssembler {
    pub fn new() -> Self {
        Self {
            temp_results: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Store a task result chunk for later assembly
    pub async fn store_chunk(&self, job_id: JobId, chunk: TaskResultChunk) {
        let mut results = self.temp_results.write().await;
        results.entry(job_id).or_insert_with(Vec::new).push(chunk);
    }

    /// Determine the assembly strategy based on job type
    fn determine_strategy(&self, job_type: &JobType) -> AssemblyStrategy {
        match job_type {
            JobType::VideoProcessing { .. } => AssemblyStrategy::Sequential,
            JobType::AudioProcessing { .. } => AssemblyStrategy::Sequential,
            JobType::Render3D { output_resolution, .. } => {
                let tile_size = self.calculate_tile_size(*output_resolution);
                AssemblyStrategy::TileStitch {
                    width: output_resolution.0,
                    height: output_resolution.1,
                    tile_size,
                }
            }
            JobType::AIInference { .. } => AssemblyStrategy::BatchMerge,
            JobType::ComputerVision { .. } => AssemblyStrategy::BatchMerge,
            JobType::NLP { .. } => AssemblyStrategy::BatchMerge,
            JobType::TimeSeriesAnalysis { .. } => AssemblyStrategy::BatchMerge,
            JobType::MultimodalAI { .. } => AssemblyStrategy::BatchMerge,
            JobType::ZKProof { .. } => AssemblyStrategy::Consensus,
            _ => AssemblyStrategy::Sequential,
        }
    }

    fn calculate_tile_size(&self, resolution: (u32, u32)) -> (u32, u32) {
        let pixels = resolution.0 * resolution.1;
        match pixels {
            0..=1000000 => (256, 256),
            1000001..=4000000 => (512, 512),
            4000001..=16000000 => (1024, 1024),
            _ => (2048, 2048),
        }
    }

    /// Assemble the final result from completed tasks
    pub async fn assemble_job_result(
        &self,
        job_id: JobId,
        tasks: &[Task],
    ) -> Result<Vec<u8>> {
        info!("Assembling results for job {} with {} tasks", job_id, tasks.len());

        if tasks.is_empty() {
            return Err(anyhow!("No tasks to assemble"));
        }

        // Verify all tasks are completed
        let incomplete_tasks: Vec<_> = tasks.iter()
            .filter(|t| t.status != TaskStatus::Completed)
            .collect();

        if !incomplete_tasks.is_empty() {
            return Err(anyhow!(
                "Cannot assemble: {} tasks are not completed",
                incomplete_tasks.len()
            ));
        }

        // Sort tasks by chunk ID to ensure proper ordering
        let mut sorted_tasks = tasks.to_vec();
        sorted_tasks.sort_by_key(|t| {
            t.input_data.chunk_info.as_ref().map(|c| c.chunk_id).unwrap_or(0)
        });

        // Get the job type from the first task
        let job_type = &sorted_tasks[0].task_type;
        let strategy = self.determine_strategy(job_type);

        debug!("Using assembly strategy: {:?} for job type: {}", strategy, job_type);

        // Get stored result chunks
        let result_chunks = {
            let results = self.temp_results.read().await;
            results.get(&job_id).cloned().unwrap_or_default()
        };

        // Assemble based on strategy
        let assembled_data = match strategy {
            AssemblyStrategy::Sequential => {
                self.assemble_sequential(&sorted_tasks, &result_chunks).await?
            }
            AssemblyStrategy::TileStitch { width, height, tile_size } => {
                self.assemble_tiles(&sorted_tasks, &result_chunks, width, height, tile_size).await?
            }
            AssemblyStrategy::BatchMerge => {
                self.assemble_batch(&sorted_tasks, &result_chunks).await?
            }
            AssemblyStrategy::Consensus => {
                self.assemble_consensus(&sorted_tasks, &result_chunks).await?
            }
            AssemblyStrategy::Custom(handler) => {
                self.assemble_custom(&sorted_tasks, &result_chunks, &handler).await?
            }
        };

        // Clean up temporary storage
        self.temp_results.write().await.remove(&job_id);

        info!("Successfully assembled {} bytes for job {}", assembled_data.len(), job_id);
        Ok(assembled_data)
    }

    /// Sequential assembly - concatenate chunks in order
    async fn assemble_sequential(
        &self,
        tasks: &[Task],
        chunks: &[TaskResultChunk],
    ) -> Result<Vec<u8>> {
        debug!("Performing sequential assembly of {} chunks", chunks.len());

        // Sort chunks by chunk_id
        let mut sorted_chunks = chunks.to_vec();
        sorted_chunks.sort_by_key(|c| c.chunk_id);

        // Verify we have all expected chunks
        let expected_count = tasks.iter()
            .filter_map(|t| t.input_data.chunk_info.as_ref())
            .map(|c| c.total_chunks)
            .max()
            .unwrap_or(tasks.len() as u32);

        if sorted_chunks.len() != expected_count as usize {
            debug!(
                "Warning: Expected {} chunks but found {}",
                expected_count, sorted_chunks.len()
            );
        }

        // Concatenate all chunk data
        let mut result = Vec::new();
        for chunk in sorted_chunks {
            result.extend(&chunk.data);
        }

        Ok(result)
    }

    /// Tile stitching - combine image tiles into a single image
    async fn assemble_tiles(
        &self,
        _tasks: &[Task],
        chunks: &[TaskResultChunk],
        width: u32,
        height: u32,
        tile_size: (u32, u32),
    ) -> Result<Vec<u8>> {
        debug!(
            "Performing tile stitch assembly: {}x{} with tiles {}x{}",
            width, height, tile_size.0, tile_size.1
        );

        let tiles_x = (width + tile_size.0 - 1) / tile_size.0;
        let tiles_y = (height + tile_size.1 - 1) / tile_size.1;
        let _total_tiles = tiles_x * tiles_y;

        // Create output buffer (assuming RGBA format, 4 bytes per pixel)
        let bytes_per_pixel = 4;
        let mut output = vec![0u8; (width * height * bytes_per_pixel) as usize];

        // Place each tile in the correct position
        for chunk in chunks {
            if let Some((tile_x, tile_y, tile_w, tile_h)) = chunk.metadata.tile_coords {
                let tile_x_pixel = tile_x * tile_size.0;
                let tile_y_pixel = tile_y * tile_size.1;

                // Copy tile data row by row
                for row in 0..tile_h.min(height - tile_y_pixel) {
                    let src_offset = (row * tile_w * bytes_per_pixel) as usize;
                    let dst_y = tile_y_pixel + row;
                    let dst_x = tile_x_pixel;
                    let dst_offset = ((dst_y * width + dst_x) * bytes_per_pixel) as usize;

                    let row_bytes = (tile_w.min(width - dst_x) * bytes_per_pixel) as usize;
                    if src_offset + row_bytes <= chunk.data.len() && dst_offset + row_bytes <= output.len() {
                        output[dst_offset..dst_offset + row_bytes]
                            .copy_from_slice(&chunk.data[src_offset..src_offset + row_bytes]);
                    }
                }
            }
        }

        debug!("Tile stitching complete: assembled {} tiles", chunks.len());
        Ok(output)
    }

    /// Batch merge - combine AI inference results
    async fn assemble_batch(
        &self,
        _tasks: &[Task],
        chunks: &[TaskResultChunk],
    ) -> Result<Vec<u8>> {
        debug!("Performing batch merge assembly of {} chunks", chunks.len());

        // Sort by batch range
        let mut sorted_chunks = chunks.to_vec();
        sorted_chunks.sort_by_key(|c| c.metadata.batch_range.map(|(start, _)| start).unwrap_or(c.chunk_id));

        // Combine results into a JSON array
        let mut combined_results: Vec<serde_json::Value> = Vec::new();

        for chunk in &sorted_chunks {
            // Try to parse each chunk as JSON
            match serde_json::from_slice::<serde_json::Value>(&chunk.data) {
                Ok(value) => {
                    if let Some(arr) = value.as_array() {
                        combined_results.extend(arr.clone());
                    } else {
                        combined_results.push(value);
                    }
                }
                Err(_) => {
                    // If not JSON, wrap raw data as hex
                    let encoded = hex::encode(&chunk.data);
                    combined_results.push(serde_json::json!({
                        "chunk_id": chunk.chunk_id,
                        "data": encoded,
                        "encoding": "hex"
                    }));
                }
            }
        }

        // Create final result structure
        let result = serde_json::json!({
            "results": combined_results,
            "total_batches": sorted_chunks.len(),
            "assembly_method": "batch_merge"
        });

        Ok(serde_json::to_vec(&result)?)
    }

    /// Consensus assembly - for ZK proofs and verified computation
    async fn assemble_consensus(
        &self,
        _tasks: &[Task],
        chunks: &[TaskResultChunk],
    ) -> Result<Vec<u8>> {
        debug!("Performing consensus assembly of {} chunks", chunks.len());

        if chunks.is_empty() {
            return Err(anyhow!("No chunks available for consensus"));
        }

        // For ZK proofs, we need to verify that results are consistent
        // Group chunks by their checksum
        let mut checksum_groups: HashMap<String, Vec<&TaskResultChunk>> = HashMap::new();

        for chunk in chunks {
            let checksum = chunk.metadata.checksum.clone()
                .unwrap_or_else(|| {
                    // Compute checksum if not provided
                    use sha2::{Sha256, Digest};
                    let mut hasher = Sha256::new();
                    hasher.update(&chunk.data);
                    hex::encode(hasher.finalize())
                });

            checksum_groups.entry(checksum).or_default().push(chunk);
        }

        // Find the group with the most agreement (majority vote)
        let (winning_checksum, winning_group) = checksum_groups
            .into_iter()
            .max_by_key(|(_, group)| group.len())
            .ok_or_else(|| anyhow!("No consensus groups found"))?;

        let total_chunks = chunks.len();
        let agreeing_chunks = winning_group.len();
        let consensus_ratio = agreeing_chunks as f64 / total_chunks as f64;

        // Require at least 2/3 majority for consensus
        if consensus_ratio < 0.67 {
            return Err(anyhow!(
                "Consensus not reached: only {:.1}% agreement (need 67%)",
                consensus_ratio * 100.0
            ));
        }

        info!(
            "Consensus reached: {}/{} chunks agree ({:.1}%)",
            agreeing_chunks, total_chunks, consensus_ratio * 100.0
        );

        // Return the consensus result with metadata
        let consensus_data = &winning_group[0].data;
        let result = serde_json::json!({
            "consensus": true,
            "checksum": winning_checksum,
            "agreement_ratio": consensus_ratio,
            "agreeing_workers": agreeing_chunks,
            "total_workers": total_chunks,
            "data": hex::encode(consensus_data),
            "encoding": "hex"
        });

        Ok(serde_json::to_vec(&result)?)
    }

    /// Custom assembly handler
    async fn assemble_custom(
        &self,
        tasks: &[Task],
        chunks: &[TaskResultChunk],
        handler: &str,
    ) -> Result<Vec<u8>> {
        debug!("Performing custom assembly with handler: {}", handler);

        // For now, fall back to sequential assembly
        // In the future, this could invoke custom assembly logic
        self.assemble_sequential(tasks, chunks).await
    }

    /// Get the number of pending chunks for a job
    pub async fn get_pending_chunk_count(&self, job_id: &JobId) -> usize {
        let results = self.temp_results.read().await;
        results.get(job_id).map(|v| v.len()).unwrap_or(0)
    }

    /// Check if all chunks are received for a job
    pub async fn has_all_chunks(&self, job_id: &JobId, expected_count: usize) -> bool {
        let results = self.temp_results.read().await;
        results.get(job_id).map(|v| v.len() >= expected_count).unwrap_or(false)
    }

    /// Clear temporary results for a job
    pub async fn clear_job_results(&self, job_id: &JobId) {
        self.temp_results.write().await.remove(job_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    #[tokio::test]
    async fn test_frame_based_splitting() {
        let splitter = JobSplitter::new();
        let job_id = JobId::new();
        let job_type = JobType::VideoProcessing {
            input_file: "test.mp4".to_string(),
            output_format: "mp4".to_string(),
            resolution: (1920, 1080),
            frame_rate: 30.0,
            duration: 10.0, // 10 seconds = 300 frames
        };

        let strategy = splitter.analyze_job(&job_type).await.unwrap();
        let tasks = splitter.split_job(job_id, &job_type, &strategy).await.unwrap();

        assert_eq!(tasks.len(), 12); // 300 frames / 25 frames per chunk = 12 tasks
    }

    #[tokio::test]
    async fn test_tile_based_splitting() {
        let splitter = JobSplitter::new();
        let job_id = JobId::new();
        let job_type = JobType::Render3D {
            scene_file: "scene.blend".to_string(),
            output_resolution: (1920, 1080),
            frames: None,
            quality_preset: "high".to_string(),
        };

        let strategy = splitter.analyze_job(&job_type).await.unwrap();
        let tasks = splitter.split_job(job_id, &job_type, &strategy).await.unwrap();

        // 1920x1080 with 512x512 tiles = 4x3 = 12 tiles
        assert_eq!(tasks.len(), 12);
    }

    #[tokio::test]
    async fn test_result_assembler_creation() {
        let assembler = ResultAssembler::new();
        let job_id = JobId::new();

        // Should start with no chunks
        assert_eq!(assembler.get_pending_chunk_count(&job_id).await, 0);
        assert!(!assembler.has_all_chunks(&job_id, 1).await);
    }

    #[tokio::test]
    async fn test_result_assembler_store_chunks() {
        let assembler = ResultAssembler::new();
        let job_id = JobId::new();

        // Create test chunks
        let chunk1 = TaskResultChunk {
            task_id: TaskId::new(),
            chunk_id: 0,
            data: vec![1, 2, 3],
            metadata: TaskResultMetadata {
                job_type: "test".to_string(),
                frame_range: Some((0, 10)),
                tile_coords: None,
                batch_range: None,
                execution_time_ms: 100,
                output_format: None,
                checksum: None,
            },
        };

        let chunk2 = TaskResultChunk {
            task_id: TaskId::new(),
            chunk_id: 1,
            data: vec![4, 5, 6],
            metadata: TaskResultMetadata {
                job_type: "test".to_string(),
                frame_range: Some((11, 20)),
                tile_coords: None,
                batch_range: None,
                execution_time_ms: 100,
                output_format: None,
                checksum: None,
            },
        };

        // Store chunks
        assembler.store_chunk(job_id.clone(), chunk1).await;
        assert_eq!(assembler.get_pending_chunk_count(&job_id).await, 1);

        assembler.store_chunk(job_id.clone(), chunk2).await;
        assert_eq!(assembler.get_pending_chunk_count(&job_id).await, 2);
        assert!(assembler.has_all_chunks(&job_id, 2).await);

        // Clear chunks
        assembler.clear_job_results(&job_id).await;
        assert_eq!(assembler.get_pending_chunk_count(&job_id).await, 0);
    }

    #[tokio::test]
    async fn test_sequential_assembly() {
        let assembler = ResultAssembler::new();
        let job_id = JobId::new();
        let task_id = TaskId::new();

        // Create completed task
        let task = Task {
            id: task_id.clone(),
            job_id: job_id.clone(),
            task_type: JobType::VideoProcessing {
                input_file: "test.mp4".to_string(),
                output_format: "mp4".to_string(),
                resolution: (1920, 1080),
                frame_rate: 30.0,
                duration: 10.0,
            },
            input_data: TaskInput {
                parameters: HashMap::new(),
                files: vec![],
                chunk_info: Some(ChunkInfo {
                    chunk_id: 0,
                    total_chunks: 2,
                    start_offset: 0,
                    end_offset: 100,
                    frame_range: Some((0, 10)),
                    tile_coords: None,
                }),
            },
            dependencies: vec![],
            estimated_duration: 60,
            estimated_memory: 1024,
            gpu_required: false,
            priority: 5,
            status: TaskStatus::Completed,
            assigned_worker: Some(WorkerId::new()),
            created_at: chrono::Utc::now(),
            started_at: Some(chrono::Utc::now()),
            completed_at: Some(chrono::Utc::now()),
        };

        // Store result chunks
        assembler.store_chunk(job_id.clone(), TaskResultChunk {
            task_id: task_id.clone(),
            chunk_id: 0,
            data: vec![1, 2, 3],
            metadata: TaskResultMetadata {
                job_type: "VideoProcessing".to_string(),
                frame_range: Some((0, 10)),
                tile_coords: None,
                batch_range: None,
                execution_time_ms: 100,
                output_format: Some("mp4".to_string()),
                checksum: None,
            },
        }).await;

        assembler.store_chunk(job_id.clone(), TaskResultChunk {
            task_id: TaskId::new(),
            chunk_id: 1,
            data: vec![4, 5, 6],
            metadata: TaskResultMetadata {
                job_type: "VideoProcessing".to_string(),
                frame_range: Some((11, 20)),
                tile_coords: None,
                batch_range: None,
                execution_time_ms: 100,
                output_format: Some("mp4".to_string()),
                checksum: None,
            },
        }).await;

        // Create a second task marked as completed
        let mut task2 = task.clone();
        task2.id = TaskId::new();
        task2.input_data.chunk_info = Some(ChunkInfo {
            chunk_id: 1,
            total_chunks: 2,
            start_offset: 100,
            end_offset: 200,
            frame_range: Some((11, 20)),
            tile_coords: None,
        });

        // Assemble results
        let result = assembler.assemble_job_result(job_id.clone(), &[task, task2]).await.unwrap();
        assert_eq!(result, vec![1, 2, 3, 4, 5, 6]);
    }

    #[tokio::test]
    async fn test_batch_merge_assembly() {
        let assembler = ResultAssembler::new();
        let job_id = JobId::new();
        let task_id = TaskId::new();

        // Create completed AI inference task
        let task = Task {
            id: task_id.clone(),
            job_id: job_id.clone(),
            task_type: JobType::AIInference {
                model_type: "test-model".to_string(),
                input_data: "test input".to_string(),
                batch_size: 10,
                parameters: HashMap::new(),
            },
            input_data: TaskInput {
                parameters: HashMap::new(),
                files: vec![],
                chunk_info: Some(ChunkInfo {
                    chunk_id: 0,
                    total_chunks: 1,
                    start_offset: 0,
                    end_offset: 10,
                    frame_range: None,
                    tile_coords: None,
                }),
            },
            dependencies: vec![],
            estimated_duration: 30,
            estimated_memory: 512,
            gpu_required: true,
            priority: 5,
            status: TaskStatus::Completed,
            assigned_worker: Some(WorkerId::new()),
            created_at: chrono::Utc::now(),
            started_at: Some(chrono::Utc::now()),
            completed_at: Some(chrono::Utc::now()),
        };

        // Store JSON result chunk
        let json_result = serde_json::json!({"predictions": [0.9, 0.1, 0.0]});
        assembler.store_chunk(job_id.clone(), TaskResultChunk {
            task_id: task_id.clone(),
            chunk_id: 0,
            data: serde_json::to_vec(&json_result).unwrap(),
            metadata: TaskResultMetadata {
                job_type: "AIInference".to_string(),
                frame_range: None,
                tile_coords: None,
                batch_range: Some((0, 10)),
                execution_time_ms: 50,
                output_format: Some("json".to_string()),
                checksum: None,
            },
        }).await;

        // Assemble results
        let result = assembler.assemble_job_result(job_id.clone(), &[task]).await.unwrap();
        let result_json: serde_json::Value = serde_json::from_slice(&result).unwrap();

        assert!(result_json.get("results").is_some());
        assert_eq!(result_json["assembly_method"], "batch_merge");
    }

    #[tokio::test]
    async fn test_consensus_assembly() {
        let assembler = ResultAssembler::new();
        let job_id = JobId::new();

        // Create completed ZK proof task
        let task = Task {
            id: TaskId::new(),
            job_id: job_id.clone(),
            task_type: JobType::ZKProof {
                circuit_type: "stark".to_string(),
                input_data: "test".to_string(),
                proof_system: "stwo".to_string(),
            },
            input_data: TaskInput {
                parameters: HashMap::new(),
                files: vec![],
                chunk_info: None,
            },
            dependencies: vec![],
            estimated_duration: 120,
            estimated_memory: 4096,
            gpu_required: true,
            priority: 10,
            status: TaskStatus::Completed,
            assigned_worker: Some(WorkerId::new()),
            created_at: chrono::Utc::now(),
            started_at: Some(chrono::Utc::now()),
            completed_at: Some(chrono::Utc::now()),
        };

        // Store three identical result chunks (simulating consensus)
        let proof_data = vec![0xde, 0xad, 0xbe, 0xef];
        for i in 0..3 {
            assembler.store_chunk(job_id.clone(), TaskResultChunk {
                task_id: TaskId::new(),
                chunk_id: i,
                data: proof_data.clone(),
                metadata: TaskResultMetadata {
                    job_type: "ZKProof".to_string(),
                    frame_range: None,
                    tile_coords: None,
                    batch_range: None,
                    execution_time_ms: 1000,
                    output_format: Some("stark_proof".to_string()),
                    checksum: Some(hex::encode(sha2::Sha256::digest(&proof_data))),
                },
            }).await;
        }

        // Assemble results (should reach consensus)
        let result = assembler.assemble_job_result(job_id.clone(), &[task]).await.unwrap();
        let result_json: serde_json::Value = serde_json::from_slice(&result).unwrap();

        assert_eq!(result_json["consensus"], true);
        assert_eq!(result_json["agreement_ratio"], 1.0);
        assert_eq!(result_json["agreeing_workers"], 3);
        assert_eq!(result_json["total_workers"], 3);
    }

    #[tokio::test]
    async fn test_assembly_strategy_determination() {
        let assembler = ResultAssembler::new();

        // Video should use Sequential
        let video_type = JobType::VideoProcessing {
            input_file: "test.mp4".to_string(),
            output_format: "mp4".to_string(),
            resolution: (1920, 1080),
            frame_rate: 30.0,
            duration: 10.0,
        };
        matches!(assembler.determine_strategy(&video_type), AssemblyStrategy::Sequential);

        // Render3D should use TileStitch
        let render_type = JobType::Render3D {
            scene_file: "scene.blend".to_string(),
            output_resolution: (1920, 1080),
            frames: None,
            quality_preset: "high".to_string(),
        };
        matches!(assembler.determine_strategy(&render_type), AssemblyStrategy::TileStitch { .. });

        // AI Inference should use BatchMerge
        let ai_type = JobType::AIInference {
            model_type: "llm".to_string(),
            input_data: "test".to_string(),
            batch_size: 32,
            parameters: HashMap::new(),
        };
        matches!(assembler.determine_strategy(&ai_type), AssemblyStrategy::BatchMerge);

        // ZK Proof should use Consensus
        let zk_type = JobType::ZKProof {
            circuit_type: "stark".to_string(),
            input_data: "test".to_string(),
            proof_system: "stwo".to_string(),
        };
        matches!(assembler.determine_strategy(&zk_type), AssemblyStrategy::Consensus);
    }
} 