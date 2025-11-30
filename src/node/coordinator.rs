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
use tracing::{info, debug};
use starknet::core::types::FieldElement;

use crate::types::{JobId, WorkerId, TaskId, TeeType};
pub use crate::types::WorkerCapabilities; // Re-export for backward compatibility
use crate::blockchain::contracts::JobManagerContract;
use crate::storage::Database;
use crate::coordinator::config::BlockchainConfig;

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

/// Main coordinator service
#[derive(Debug, Clone)]
pub struct JobCoordinator {
    database: Arc<Database>,
    job_manager: Arc<JobManagerContract>,
    blockchain_config: BlockchainConfig,
    active_jobs: Arc<RwLock<HashMap<JobId, JobState>>>,
    task_queue: Arc<RwLock<Vec<Task>>>,
    worker_pool: Arc<RwLock<HashMap<WorkerId, WorkerInfo>>>,
    job_splitter: JobSplitter,
    result_assembler: ResultAssembler,
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
}

impl JobCoordinator {
    /// Create a new JobCoordinator
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
        }
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

        Ok(JobResult {
            job_id,
            status: job_state.status.clone(),
            completed_tasks,
            total_tasks: job_state.tasks.len() as u32,
            output_files: Vec::new(), // TODO: Implement
            execution_time: 0, // TODO: Calculate
            total_cost: 0, // TODO: Calculate
            error_message: None,
        })
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
            .min_by(|a, b| a.current_load.partial_cmp(&b.current_load).unwrap())
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
        let mut jobs = self.active_jobs.write().await;
        if let Some(job_state) = jobs.get_mut(&job_id) {
            let completed_tasks = job_state.tasks.iter()
                .filter(|t| t.status == TaskStatus::Completed)
                .count();

            if completed_tasks == job_state.tasks.len() {
                job_state.status = JobStatus::Completed;

                // Assemble final result
                let final_result = self.result_assembler
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
                };

                // Notify blockchain
                let private_key = self.parse_private_key()?;
                let account_address = self.parse_account_address()?;
                self.job_manager.complete_job(job_id, &job_result, private_key, account_address).await?;
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
                estimated_duration: 60, // TODO: Better estimation
                estimated_memory: 1024, // TODO: Better estimation
                gpu_required: matches!(job_type, JobType::Render3D { .. } | JobType::AIInference { .. }),
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

/// Result assembly logic
#[derive(Debug, Clone)]
pub struct ResultAssembler;

impl ResultAssembler {
    pub fn new() -> Self {
        Self
    }

    /// Assemble the final result from completed tasks
    pub async fn assemble_job_result(
        &self,
        job_id: JobId,
        tasks: &[Task],
    ) -> Result<Vec<u8>> {
        info!("Assembling results for job {}", job_id);
        
        // Sort tasks by chunk ID to ensure proper ordering
        let mut sorted_tasks = tasks.to_vec();
        sorted_tasks.sort_by_key(|t| {
            t.input_data.chunk_info.as_ref().map(|c| c.chunk_id).unwrap_or(0)
        });

        // TODO: Implement actual result assembly based on job type
        // For now, return empty result
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
} 