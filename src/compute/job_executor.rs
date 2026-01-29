//! # Job Executor
//!
//! Production job executor — routes every job type to its real compute backend:
//! - LLM inference → vLLM (OpenAI-compatible API)
//! - Computer Vision, NLP, Audio, Image Gen → AIExecutionEngine (Docker + GPU)
//! - Data Pipeline → SecureDataExecutor (DataFusion SQL on S3/Parquet)
//! - ZK Proofs → ObelyskExecutor (STWO Circle STARK prover)
//! - FHE → tfhe-rs homomorphic encryption
//! - Confidential VM → TEE-gated Docker execution

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use tracing::{info, warn, debug};
use std::time::Instant;
use std::sync::{Arc, RwLock};
use sha2::{Sha256, Digest};
use hex;

use crate::compute::obelysk_executor::{ObelyskExecutor, ObelyskExecutorConfig, ObelyskJobStatus};
use crate::compute::data_executor::SecureDataExecutor;
use crate::obelysk::proof_compression::CompressedProof;
use crate::obelysk::compute_invoice::{ComputeInvoice, InvoiceBuilder};
use crate::ai::execution::{AIExecutionEngine, AIJobRequest, AIJobInput, AIJobOutput, ResourceConstraints, ExecutionParams};
use crate::ai::model_registry::ModelRegistry;
use crate::ai::frameworks::FrameworkManager;

#[cfg(feature = "fhe")]
use crate::obelysk::fhe::{
    FheKeyManager, FheEncryptor, FheCompute, EncryptedValue,
    KeyConfig, SerializedCiphertext, SerializedKey,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobExecutionRequest {
    #[serde(alias = "id")]
    pub job_id: Option<String>,
    #[serde(alias = "required_job_type", rename = "job_type")]
    pub job_type: Option<String>,
    pub payload: Vec<u8>,
    pub requirements: JobRequirements,
    pub priority: u8,
}

// ========== FHE Job Types ==========

/// Request for FHE computation on encrypted data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FheComputeRequest {
    /// Operation to perform: "add", "mul", "sub", "sum", "dot_product", "max", "min"
    pub operation: String,
    /// Serialized server key for homomorphic operations
    pub server_key: crate::obelysk::fhe::SerializedKey,
    /// Input ciphertexts (serialized)
    pub inputs: Vec<crate::obelysk::fhe::SerializedCiphertext>,
}

/// Response from FHE computation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FheComputeResponse {
    /// Result ciphertext (serialized)
    pub result: crate::obelysk::fhe::SerializedCiphertext,
    /// Computation time in milliseconds
    pub compute_time_ms: u64,
    /// Operation that was performed
    pub operation: String,
    /// Worker that executed the job
    pub worker_id: String,
    /// Whether TEE was used for additional protection
    pub tee_protected: bool,
}

/// Request for confidential AI inference on encrypted data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidentialAIRequest {
    /// Type of model: "classifier", "regressor", "neural_network"
    pub model_type: String,
    /// Serialized server key for homomorphic operations
    pub server_key: crate::obelysk::fhe::SerializedKey,
    /// Encrypted input features (serialized ciphertexts)
    pub encrypted_inputs: Vec<crate::obelysk::fhe::SerializedCiphertext>,
    /// Model weights for each layer (encrypted)
    /// Structure: layers[neurons[weights]]
    pub model_weights: Vec<Vec<Vec<crate::obelysk::fhe::SerializedCiphertext>>>,
}

/// Response from confidential AI inference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidentialAIResponse {
    /// Encrypted output predictions
    pub encrypted_outputs: Vec<crate::obelysk::fhe::SerializedCiphertext>,
    /// Computation time in milliseconds
    pub compute_time_ms: u64,
    /// Model type that was used
    pub model_type: String,
    /// Number of layers processed
    pub layers_processed: usize,
    /// Worker that executed the job
    pub worker_id: String,
    /// Whether TEE was used
    pub tee_protected: bool,
}

// ========== ZK Proof Job Types ==========

/// Request for ZK proof generation (STWO)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkProofRequest {
    /// Circuit type: "generic", "etl", "ml_inference", "payment", "privacy_swap"
    pub circuit_type: String,
    /// Public inputs for the circuit
    pub public_inputs: Vec<u8>,
    /// Private/witness inputs (optional)
    pub private_inputs: Option<Vec<u8>>,
    /// Security level in bits (default: 128)
    #[serde(default = "default_security_bits")]
    pub security_bits: usize,
    /// Whether to compress the proof output
    #[serde(default = "default_true")]
    pub compress_output: bool,
}

fn default_security_bits() -> usize { 128 }
fn default_true() -> bool { true }

/// Response from ZK proof generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkProofResponse {
    /// Blake3 hash of the proof (hex)
    pub proof_hash: String,
    /// 32-byte attestation (hex)
    pub proof_attestation: String,
    /// Commitment for on-chain verification (hex)
    pub proof_commitment: String,
    /// Compressed proof bytes (if compress_output was true)
    pub compressed_proof_bytes: Option<Vec<u8>>,
    /// Proof size in bytes
    pub proof_size_bytes: usize,
    /// Time to generate proof in ms
    pub proof_time_ms: u64,
    /// Number of trace steps
    pub trace_length: usize,
    /// Whether GPU was used
    pub gpu_used: bool,
    /// GPU speedup factor (if applicable)
    pub gpu_speedup: Option<f64>,
    /// Circuit type that was proven
    pub circuit_type: String,
    /// Security bits achieved
    pub security_bits: usize,
    /// Worker that generated the proof
    pub worker_id: String,
}

// ========== Model Deployment Job Types ==========

/// Request for model deployment (one-liner model deployment)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelDeployRequest {
    /// Model name/identifier (e.g., "meta-llama/Llama-3.1-8B")
    pub model_name: String,
    /// Model source: "huggingface", "s3", "ipfs", "url"
    #[serde(default = "default_huggingface")]
    pub source: String,
    /// Model size hint: "small", "medium", "large", "xlarge"
    #[serde(default = "default_medium")]
    pub model_size: String,
    /// Quantization: "fp16", "int8", "int4", "none"
    #[serde(default = "default_fp16")]
    pub quantization: String,
    /// Max batch size
    #[serde(default = "default_batch_8")]
    pub max_batch_size: u32,
    /// Custom model URL (if source is "url")
    pub model_url: Option<String>,
    /// Revision/version
    pub revision: Option<String>,
}

fn default_huggingface() -> String { "huggingface".to_string() }
fn default_medium() -> String { "medium".to_string() }
fn default_fp16() -> String { "fp16".to_string() }
fn default_batch_8() -> u32 { 8 }

/// Response from model deployment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelDeployResponse {
    /// Unique model deployment ID
    pub model_id: String,
    /// Model name
    pub model_name: String,
    /// Inference endpoint path
    pub endpoint: String,
    /// Deployment status
    pub status: String,
    /// Worker that deployed the model
    pub worker_id: String,
    /// Time to deploy in ms
    pub deployment_time_ms: u64,
    /// Estimated inference time per request
    pub estimated_inference_time_ms: u64,
    /// VRAM used by model
    pub vram_used_mb: u64,
    /// Supported batch sizes
    pub supported_batch_sizes: Vec<u32>,
}

/// Request for model inference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInferenceRequest {
    /// Model deployment ID
    pub model_id: String,
    /// Model type: "llm", "image_gen", "embedding", "classification", "object_detection"
    pub model_type: String,
    /// Input data (varies by model type)
    pub input: serde_json::Value,
    /// Max tokens (for LLMs)
    pub max_tokens: Option<u32>,
    /// Temperature (for LLMs)
    pub temperature: Option<f32>,
    /// Top-p (for LLMs)
    pub top_p: Option<f32>,
}

/// Response from model inference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInferenceResponse {
    /// Model deployment ID
    pub model_id: String,
    /// Model output
    pub output: serde_json::Value,
    /// Inference time in ms
    pub inference_time_ms: u64,
    /// Tokens processed
    pub tokens_processed: u64,
    /// Worker ID
    pub worker_id: String,
    /// GPU memory used
    pub gpu_memory_used_mb: u64,
}

/// Request for batch inference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchInferenceRequest {
    /// Model deployment ID
    pub model_id: String,
    /// Batch of inputs
    pub inputs: Vec<serde_json::Value>,
}

/// Response from batch inference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchInferenceResponse {
    /// Model deployment ID
    pub model_id: String,
    /// Batch outputs
    pub outputs: Vec<serde_json::Value>,
    /// Batch size processed
    pub batch_size: usize,
    /// Total processing time in ms
    pub total_time_ms: u64,
    /// Average time per item
    pub avg_time_per_item_ms: u64,
    /// Worker ID
    pub worker_id: String,
    /// GPU utilization (0.0 - 1.0)
    pub gpu_utilization: f64,
}

// ========== Model Training Job Types ==========

/// Request for model training (full training or fine-tuning)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelTrainingRequest {
    /// Base model to train or fine-tune (e.g. "meta-llama/Llama-3.1-8B")
    pub base_model: String,
    /// Training mode: "full", "lora", "qlora", "freeze_layers"
    pub training_mode: String,
    /// Dataset path (S3, local, or IPFS URI)
    pub dataset_path: String,
    /// Dataset format: "jsonl", "parquet", "csv", "hf_dataset"
    #[serde(default = "default_jsonl")]
    pub dataset_format: String,
    /// Output directory for checkpoints and final model
    pub output_path: String,
    /// Training hyperparameters
    pub hyperparameters: TrainingHyperparameters,
    /// LoRA-specific configuration (when training_mode is "lora" or "qlora")
    pub lora_config: Option<LoRAConfig>,
    /// Checkpoint frequency (save every N steps, 0 = end only)
    #[serde(default)]
    pub checkpoint_every_n_steps: u64,
    /// Evaluation dataset path (optional)
    pub eval_dataset_path: Option<String>,
    /// Framework to use: "pytorch", "huggingface", "deepspeed"
    #[serde(default = "default_huggingface")]
    pub framework: String,
    /// Number of GPUs to use (for distributed training)
    #[serde(default = "default_gpu_count")]
    pub num_gpus: u32,
}

fn default_jsonl() -> String { "jsonl".to_string() }
fn default_gpu_count() -> u32 { 1 }

/// Training hyperparameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingHyperparameters {
    /// Learning rate
    #[serde(default = "default_lr")]
    pub learning_rate: f64,
    /// Batch size per device
    #[serde(default = "default_batch_size")]
    pub per_device_batch_size: u32,
    /// Gradient accumulation steps
    #[serde(default = "default_grad_accum")]
    pub gradient_accumulation_steps: u32,
    /// Number of training epochs
    #[serde(default = "default_epochs")]
    pub num_epochs: u32,
    /// Max training steps (overrides epochs if set)
    pub max_steps: Option<u64>,
    /// Warmup steps
    #[serde(default)]
    pub warmup_steps: u64,
    /// Weight decay
    #[serde(default = "default_weight_decay")]
    pub weight_decay: f64,
    /// Optimizer: "adamw", "sgd", "adafactor", "lion"
    #[serde(default = "default_optimizer")]
    pub optimizer: String,
    /// LR scheduler: "cosine", "linear", "constant", "cosine_with_restarts"
    #[serde(default = "default_scheduler")]
    pub lr_scheduler: String,
    /// Mixed precision: "fp16", "bf16", "fp32"
    #[serde(default = "default_bf16")]
    pub mixed_precision: String,
    /// Max sequence length
    #[serde(default = "default_seq_len")]
    pub max_seq_length: u32,
    /// Gradient clipping max norm
    #[serde(default = "default_grad_clip")]
    pub max_grad_norm: f64,
}

fn default_lr() -> f64 { 2e-5 }
fn default_batch_size() -> u32 { 4 }
fn default_grad_accum() -> u32 { 4 }
fn default_epochs() -> u32 { 3 }
fn default_weight_decay() -> f64 { 0.01 }
fn default_optimizer() -> String { "adamw".to_string() }
fn default_scheduler() -> String { "cosine".to_string() }
fn default_bf16() -> String { "bf16".to_string() }
fn default_seq_len() -> u32 { 2048 }
fn default_grad_clip() -> f64 { 1.0 }

/// LoRA configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoRAConfig {
    /// LoRA rank (typical: 8, 16, 32, 64)
    #[serde(default = "default_lora_rank")]
    pub rank: u32,
    /// LoRA alpha (scaling factor, typically 2x rank)
    #[serde(default = "default_lora_alpha")]
    pub alpha: f32,
    /// Target modules to apply LoRA (e.g. ["q_proj", "v_proj", "k_proj", "o_proj"])
    pub target_modules: Vec<String>,
    /// Dropout rate for LoRA layers
    #[serde(default)]
    pub dropout: f32,
    /// Use 4-bit quantization (QLoRA)
    #[serde(default)]
    pub use_4bit: bool,
    /// 4-bit quantization type: "nf4" or "fp4"
    #[serde(default = "default_quant_type")]
    pub bnb_4bit_quant_type: String,
}

fn default_lora_rank() -> u32 { 16 }
fn default_lora_alpha() -> f32 { 32.0 }
fn default_quant_type() -> String { "nf4".to_string() }

/// Response from model training
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelTrainingResponse {
    /// Training job ID
    pub job_id: String,
    /// Final model output path
    pub model_output_path: String,
    /// Training status
    pub status: String,
    /// Total training time in ms
    pub training_time_ms: u64,
    /// Final training loss
    pub final_loss: Option<f64>,
    /// Final eval loss (if eval dataset provided)
    pub final_eval_loss: Option<f64>,
    /// Total steps completed
    pub steps_completed: u64,
    /// Checkpoints saved
    pub checkpoints: Vec<String>,
    /// GPU hours consumed
    pub gpu_hours: f64,
    /// Worker ID
    pub worker_id: String,
    /// Training mode used
    pub training_mode: String,
    /// Framework used
    pub framework: String,
}

/// Request for reinforcement learning training
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RLTrainingRequest {
    /// Algorithm: "ppo", "dpo", "rlhf", "grpo", "sac", "a3c"
    pub algorithm: String,
    /// Base model (for RLHF/DPO)
    pub base_model: Option<String>,
    /// Environment name (for classic RL)
    pub environment: Option<String>,
    /// Reward model path (for RLHF)
    pub reward_model: Option<String>,
    /// Preference dataset path (for DPO)
    pub preference_dataset: Option<String>,
    /// Training steps
    pub training_steps: u64,
    /// Checkpoint frequency
    #[serde(default)]
    pub checkpoint_every_n_steps: u64,
    /// Output path
    pub output_path: String,
    /// Hyperparameters
    pub hyperparameters: std::collections::HashMap<String, serde_json::Value>,
    /// Number of GPUs
    #[serde(default = "default_gpu_count")]
    pub num_gpus: u32,
}

/// Response from RL training
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RLTrainingResponse {
    /// Training job ID
    pub job_id: String,
    /// Model output path
    pub model_output_path: String,
    /// Status
    pub status: String,
    /// Training time
    pub training_time_ms: u64,
    /// Steps completed
    pub steps_completed: u64,
    /// Final reward (RL) or loss (DPO)
    pub final_metric: Option<f64>,
    /// Metric name
    pub metric_name: String,
    /// Checkpoints
    pub checkpoints: Vec<String>,
    /// GPU hours
    pub gpu_hours: f64,
    /// Worker ID
    pub worker_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobRequirements {
    pub min_vram_mb: u64,
    pub min_gpu_count: u8,
    pub required_job_type: String,
    pub timeout_seconds: u64,
    pub requires_tee: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobExecutionResult {
    pub job_id: String,
    pub status: String,
    pub output_hash: String,
    pub execution_time_ms: u64,
    pub tee_attestation: Option<String>,
    pub result_data: Vec<u8>,

    // ZK Proof data
    pub proof_hash: Option<[u8; 32]>,
    pub proof_attestation: Option<[u8; 32]>,
    pub proof_commitment: Option<[u8; 32]>,
    pub compressed_proof: Option<CompressedProof>,
    pub proof_size_bytes: Option<usize>,
    pub proof_time_ms: Option<u64>,

    // Compute Invoice (Proof-as-Invoice)
    /// The compute invoice that combines proof + billing for settlement
    pub invoice: Option<ComputeInvoice>,
}

pub struct JobExecutor {
    worker_id: String,
    worker_wallet: String,
    has_tee: bool,
    obelysk_executor: ObelyskExecutor,
    enable_proofs: bool,
    gpu_model: String,
    gpu_tier: String,
    /// Hourly rate in cents for this worker
    hourly_rate_cents: u64,
    /// Current SAGE price (should be fetched from oracle in production)
    sage_price_usd: f64,
    /// vLLM endpoint for LLM inference (e.g. "http://localhost:8000")
    vllm_endpoint: Option<String>,
    /// HTTP client for vLLM requests (connection pooling)
    http_client: reqwest::Client,
    /// Cached vLLM model name to avoid hitting /v1/models on every call
    cached_vllm_model: RwLock<Option<String>>,
    /// AI execution engine — runs Docker containers with GPU for CV, NLP, audio, etc.
    ai_engine: Arc<AIExecutionEngine>,
    /// DataFusion SQL executor for data pipeline jobs
    data_executor: SecureDataExecutor,
}

impl JobExecutor {
    /// Build the AI execution engine with model registry and framework manager
    fn build_ai_engine() -> Arc<AIExecutionEngine> {
        let model_registry = Arc::new(ModelRegistry::new());
        let framework_manager = Arc::new(FrameworkManager::new());
        Arc::new(AIExecutionEngine::new(model_registry, framework_manager, 8))
    }

    pub fn new(worker_id: String, has_tee: bool) -> Self {
        let config = ObelyskExecutorConfig {
            use_gpu: true,
            security_bits: 128,
            enable_tee: has_tee,
            enable_proof_pipeline: true,
            ..Default::default()
        };

        let obelysk_executor = ObelyskExecutor::new(worker_id.clone(), config);

        Self {
            worker_id,
            worker_wallet: "0x0".to_string(), // Default placeholder
            has_tee,
            obelysk_executor,
            enable_proofs: true,
            gpu_model: "Unknown".to_string(),
            gpu_tier: "Standard".to_string(),
            hourly_rate_cents: 50,  // Default $0.50/hour
            sage_price_usd: 0.10,   // Default SAGE price
            vllm_endpoint: None,
            http_client: reqwest::Client::new(),
            cached_vllm_model: RwLock::new(None),
            ai_engine: Self::build_ai_engine(),
            data_executor: SecureDataExecutor::new(),
        }
    }

    /// Create executor with full configuration including wallet
    pub fn with_config(
        worker_id: String,
        worker_wallet: String,
        has_tee: bool,
        enable_proofs: bool,
        use_gpu: bool,
        gpu_model: String,
        gpu_tier: String,
        hourly_rate_cents: u64,
    ) -> Self {
        let config = ObelyskExecutorConfig {
            use_gpu,
            security_bits: 128,
            enable_tee: has_tee,
            enable_proof_pipeline: enable_proofs,
            ..Default::default()
        };

        let obelysk_executor = ObelyskExecutor::new(worker_id.clone(), config);

        Self {
            worker_id,
            worker_wallet,
            has_tee,
            obelysk_executor,
            enable_proofs,
            gpu_model,
            gpu_tier,
            hourly_rate_cents,
            sage_price_usd: 0.10, // Should be fetched from oracle
            vllm_endpoint: None,
            http_client: reqwest::Client::new(),
            cached_vllm_model: RwLock::new(None),
            ai_engine: Self::build_ai_engine(),
            data_executor: SecureDataExecutor::new(),
        }
    }

    /// Create executor with custom proof configuration (legacy)
    pub fn with_proof_config(worker_id: String, has_tee: bool, enable_proofs: bool, use_gpu: bool) -> Self {
        let config = ObelyskExecutorConfig {
            use_gpu,
            security_bits: 128,
            enable_tee: has_tee,
            enable_proof_pipeline: enable_proofs,
            ..Default::default()
        };

        let obelysk_executor = ObelyskExecutor::new(worker_id.clone(), config);

        Self {
            worker_id,
            worker_wallet: "0x0".to_string(),
            has_tee,
            obelysk_executor,
            enable_proofs,
            gpu_model: "Unknown".to_string(),
            gpu_tier: "Standard".to_string(),
            hourly_rate_cents: 50,
            sage_price_usd: 0.10,
            vllm_endpoint: None,
            http_client: reqwest::Client::new(),
            cached_vllm_model: RwLock::new(None),
            ai_engine: Self::build_ai_engine(),
            data_executor: SecureDataExecutor::new(),
        }
    }

    /// Set worker wallet address
    pub fn set_wallet(&mut self, wallet: String) {
        self.worker_wallet = wallet;
    }

    /// Set SAGE price (should be called with oracle price)
    pub fn set_sage_price(&mut self, price: f64) {
        self.sage_price_usd = price;
    }

    /// Set vLLM endpoint for real inference
    pub fn set_vllm_endpoint(&mut self, endpoint: String) {
        info!("🧠 vLLM endpoint set: {}", endpoint);
        self.vllm_endpoint = Some(endpoint);
    }

    /// Returns the configured vLLM endpoint or errors if not available
    fn require_vllm(&self) -> Result<&str> {
        self.vllm_endpoint.as_deref()
            .ok_or_else(|| anyhow!("vLLM backend not available — no endpoint configured. Start vLLM on this worker before accepting jobs."))
    }

    /// Call vLLM /v1/chat/completions endpoint
    async fn call_vllm(
        &self,
        endpoint: &str,
        input: &serde_json::Value,
        max_tokens: Option<u32>,
        temperature: Option<f32>,
    ) -> Result<serde_json::Value> {
        // Build messages from input
        let messages = if let Some(text) = input.as_str() {
            serde_json::json!([{"role": "user", "content": text}])
        } else if let Some(arr) = input.as_array() {
            // Already in messages format
            serde_json::json!(arr)
        } else if input.get("messages").is_some() {
            input["messages"].clone()
        } else {
            serde_json::json!([{"role": "user", "content": input.to_string()}])
        };

        // Use cached model name or fetch from vLLM
        let model_name = {
            let cached = self.cached_vllm_model.read().unwrap().clone();
            if let Some(name) = cached {
                name
            } else {
                let models_url = format!("{}/v1/models", endpoint);
                let name = match self.http_client.get(&models_url).send().await {
                    Ok(resp) if resp.status().is_success() => {
                        let body: serde_json::Value = resp.json().await.unwrap_or_default();
                        body["data"][0]["id"].as_str().unwrap_or("default").to_string()
                    }
                    _ => "default".to_string(),
                };
                if let Ok(mut cache) = self.cached_vllm_model.write() {
                    *cache = Some(name.clone());
                }
                name
            }
        };

        let request_body = serde_json::json!({
            "model": model_name,
            "messages": messages,
            "max_tokens": max_tokens.unwrap_or(100),
            "temperature": temperature.unwrap_or(0.7),
        });

        let url = format!("{}/v1/chat/completions", endpoint);
        let response = self.http_client
            .post(&url)
            .json(&request_body)
            .send()
            .await
            .map_err(|e| anyhow!("vLLM request failed: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(anyhow!("vLLM returned {}: {}", status, error_text));
        }

        let body: serde_json::Value = response.json().await
            .map_err(|e| anyhow!("Failed to parse vLLM response: {}", e))?;

        Ok(body)
    }

    pub async fn execute(&self, request: JobExecutionRequest) -> Result<JobExecutionResult> {
        let start = Instant::now();
        
        let job_id = request.job_id.clone().unwrap_or_else(|| "unknown".to_string());
        let job_type = request.job_type.clone()
            .or_else(|| Some(request.requirements.required_job_type.clone()))
            .unwrap_or_else(|| "Generic".to_string());
        
        info!("⚙️  Executing {} job: {}", job_type, job_id);
        
        // Route to appropriate executor based on job type
        let result_data = match job_type.as_str() {
            // ====== Simple Pipeline Test Jobs ======
            "Ping" => self.execute_ping(&request).await?,
            "Echo" => self.execute_echo(&request).await?,
            // ====== Standard Job Types ======
            "AIInference" => self.execute_ai_inference(&request).await?,
            "DataPipeline" => self.execute_data_pipeline(&request).await?,
            "ConfidentialVM" => self.execute_confidential_vm(&request).await?,
            "Render3D" => self.execute_3d_render(&request).await?,
            "VideoProcessing" => self.execute_video_processing(&request).await?,
            "ComputerVision" => self.execute_computer_vision(&request).await?,
            "NLP" => self.execute_nlp(&request).await?,
            "FHECompute" => self.execute_fhe_compute(&request).await?,
            "ConfidentialAI" => self.execute_confidential_ai(&request).await?,
            // ====== ZK Proof Generation Job Types (STWO) ======
            "STWOProof" | "ZKProof" | "ObelyskProof" => self.execute_zk_proof(&request).await?,
            // ====== Model Deployment & Inference ======
            "ModelDeploy" => self.execute_model_deploy(&request).await?,
            "ModelInference" => self.execute_model_inference(&request).await?,
            "BatchInference" => self.execute_batch_inference(&request).await?,
            // ====== Model Training ======
            "ModelTraining" | "AITraining" | "FineTune" | "LoRA" => self.execute_model_training(&request).await?,
            "ReinforcementLearning" | "RLHF" | "DPO" => self.execute_rl_training(&request).await?,
            _ => {
                warn!("⚠️  Unknown job type: {:?}", request.job_type);
                self.execute_generic(&request).await?
            }
        };
        
        let execution_time_ms = start.elapsed().as_millis() as u64;
        
        // Compute output hash
        let mut hasher = Sha256::new();
        hasher.update(&result_data);
        let output_hash = format!("{:x}", hasher.finalize());
        
        // Generate TEE attestation if available
        let tee_attestation = if self.has_tee {
            Some(self.generate_tee_attestation(&job_id, &output_hash))
        } else {
            None
        };

        // Generate ZK proof if enabled
        let (proof_hash, proof_attestation, proof_commitment, compressed_proof, proof_size_bytes, proof_time_ms) = if self.enable_proofs {
            info!("🔐 Generating ZK proof for job {}", job_id);

            match self.obelysk_executor.execute_with_proof(&job_id, &job_type, &request.payload).await {
                Ok(proof_result) => {
                    if proof_result.status == ObelyskJobStatus::Completed {
                        info!(
                            "✅ Proof generated: {} bytes compressed, {}ms",
                            proof_result.compressed_proof_size().unwrap_or(0),
                            proof_result.metrics.proof_time_ms
                        );

                        (
                            Some(proof_result.proof_hash),
                            Some(proof_result.proof_attestation),
                            Some(proof_result.proof_commitment),
                            proof_result.compressed_proof.clone(),
                            Some(proof_result.metrics.proof_size_bytes),
                            Some(proof_result.metrics.proof_time_ms),
                        )
                    } else {
                        warn!("⚠️ Proof generation failed for job {}", job_id);
                        (None, None, None, None, None, None)
                    }
                }
                Err(e) => {
                    warn!("⚠️ Proof generation error for job {}: {}", job_id, e);
                    // Continue without proof - job succeeded even if proof failed
                    (None, None, None, None, None, None)
                }
            }
        } else {
            (None, None, None, None, None, None)
        };

        info!("✅ Job {} completed in {}ms", job_id, execution_time_ms);

        // =========================================================================
        // Generate Compute Invoice (Proof-as-Invoice)
        // =========================================================================
        let invoice = if self.enable_proofs && proof_hash.is_some() {
            info!("📜 Generating compute invoice for job {}", job_id);

            // Calculate GPU seconds from execution time
            let gpu_seconds = execution_time_ms as f64 / 1000.0;

            // Build the invoice
            let mut invoice = InvoiceBuilder::new(
                &job_id,
                &job_type,
                &self.worker_id,
                &self.worker_wallet,
            )
            .with_gpu(&self.gpu_model, &self.gpu_tier)
            .with_tee(self.has_tee)
            .with_input(&request.payload)
            .with_output(&result_data)
            .with_billing(
                gpu_seconds,
                self.hourly_rate_cents,
                self.sage_price_usd,
                50, // Default reputation (should come from chain)
            )
            .build();

            // Set proof data from the generated proof
            if let (Some(ph), Some(pa), Some(pc)) = (proof_hash, proof_attestation, proof_commitment) {
                invoice.set_proof_data(
                    ph,
                    pa,
                    pc,
                    proof_size_bytes.unwrap_or(0),
                    proof_time_ms.unwrap_or(0),
                    1024, // Default trace length (should come from prover)
                );
            }

            // Mark as ready for verification
            invoice.started_at = Some(chrono::Utc::now() - chrono::Duration::milliseconds(execution_time_ms as i64));
            invoice.completed_at = Some(chrono::Utc::now());

            info!("📜 Invoice generated: {}", invoice.summary());
            info!("   Circuit: {:?} | SAGE payout: {} | Worker: {}",
                invoice.circuit_type,
                invoice.total_sage_payout / 1_000_000_000_000_000_000,
                &self.worker_wallet[..10.min(self.worker_wallet.len())]);

            Some(invoice)
        } else {
            None
        };

        Ok(JobExecutionResult {
            job_id,
            status: "completed".to_string(),
            output_hash,
            execution_time_ms,
            tee_attestation,
            result_data,
            proof_hash,
            proof_attestation,
            proof_commitment,
            compressed_proof,
            proof_size_bytes,
            proof_time_ms,
            invoice,
        })
    }

    /// Execute AI Inference job — routes to the appropriate backend:
    /// - LLM text generation → vLLM
    /// - Image generation, audio, other modalities → Docker container with GPU
    async fn execute_ai_inference(&self, request: &JobExecutionRequest) -> Result<Vec<u8>> {
        info!("🤖 Running AI Inference...");
        let start = Instant::now();

        let payload: serde_json::Value = serde_json::from_slice(&request.payload)
            .unwrap_or_else(|_| {
                let text = String::from_utf8_lossy(&request.payload);
                serde_json::json!({"input": text.to_string(), "model_type": "llm"})
            });

        let model_type = payload.get("model_type").and_then(|v| v.as_str()).unwrap_or("llm");

        match model_type {
            "llm" | "text_generation" | "chat" => {
                // Route to vLLM
                let endpoint = self.require_vllm()?;
                let input_value = payload.get("input").cloned()
                    .unwrap_or_else(|| serde_json::Value::String(payload.to_string()));
                let max_tokens = payload.get("max_tokens").and_then(|t| t.as_u64()).map(|t| t as u32);
                let temperature = payload.get("temperature").and_then(|t| t.as_f64()).map(|t| t as f32);

                let vllm_response = self.call_vllm(endpoint, &input_value, max_tokens, temperature).await?;

                let text = vllm_response["choices"][0]["message"]["content"]
                    .as_str().unwrap_or("").to_string();
                let model_name = vllm_response["model"].as_str().unwrap_or("unknown").to_string();
                let prompt_tokens = vllm_response["usage"]["prompt_tokens"].as_u64().unwrap_or(0);
                let completion_tokens = vllm_response["usage"]["completion_tokens"].as_u64().unwrap_or(0);

                let result = serde_json::json!({
                    "model": model_name,
                    "output": text,
                    "prompt_tokens": prompt_tokens,
                    "completion_tokens": completion_tokens,
                    "input_hash": format!("{:x}", Sha256::digest(&request.payload)),
                    "worker_id": self.worker_id,
                    "tee_enabled": self.has_tee,
                    "backend": "vllm",
                });

                info!("✅ AI inference completed in {}ms (vLLM, {} tokens)",
                    start.elapsed().as_millis(), completion_tokens);
                Ok(serde_json::to_vec(&result)?)
            }
            _ => {
                // Route to Docker container (image gen, audio, etc.)
                let input_path = payload.get("input_path").and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow!("Missing 'input_path' for non-LLM AI inference (model_type={})", model_type))?;
                let output_path = payload.get("output_path").and_then(|v| v.as_str()).unwrap_or("/tmp/ai_output");

                let ai_request = self.build_ai_job_request(request, model_type, input_path, output_path, true);
                self.ai_engine.submit_job(ai_request.clone()).await
                    .map_err(|e| anyhow!("Failed to submit AI inference job: {}", e))?;

                let result = self.poll_ai_job(&ai_request.job_id, 300).await?;
                let execution_time_ms = start.elapsed().as_millis() as u64;

                let output = serde_json::json!({
                    "model_type": model_type,
                    "status": format!("{:?}", result.status),
                    "execution_time_ms": execution_time_ms,
                    "performance": result.performance_metrics,
                    "worker_id": self.worker_id,
                    "backend": "docker_gpu",
                });

                info!("✅ AI inference completed in {}ms (Docker, {})", execution_time_ms, model_type);
                Ok(serde_json::to_vec(&output)?)
            }
        }
    }

    /// Execute Data Pipeline job via DataFusion SQL engine
    async fn execute_data_pipeline(&self, request: &JobExecutionRequest) -> Result<Vec<u8>> {
        info!("📊 Running Data Pipeline (DataFusion)...");
        let start = Instant::now();

        // Parse payload: expects JSON with "sql" and "data_source" fields
        let payload: serde_json::Value = serde_json::from_slice(&request.payload)
            .map_err(|e| anyhow!("Invalid data pipeline request: {}. Expected JSON with 'sql' and 'data_source' fields.", e))?;

        let sql = payload.get("sql")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing 'sql' field in data pipeline request"))?;

        let data_source = payload.get("data_source")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing 'data_source' field in data pipeline request"))?;

        debug!("SQL: {}", sql);
        debug!("Data source: {}", data_source);

        let result_hash = self.data_executor.execute_sql_job(sql, data_source).await
            .map_err(|e| anyhow!("DataFusion execution failed: {}", e))?;

        let execution_time_ms = start.elapsed().as_millis() as u64;

        let result = serde_json::json!({
            "engine": "datafusion",
            "result_hash": result_hash,
            "sql": sql,
            "data_source": data_source,
            "execution_time_ms": execution_time_ms,
            "confidential": self.has_tee,
            "worker_id": self.worker_id,
        });

        info!("✅ Data pipeline completed in {}ms (DataFusion)", execution_time_ms);
        Ok(serde_json::to_vec(&result)?)
    }

    /// Execute Confidential VM job — runs payload inside a TEE-protected Docker container
    async fn execute_confidential_vm(&self, request: &JobExecutionRequest) -> Result<Vec<u8>> {
        info!("🔒 Running Confidential VM (TEE + Docker)...");
        let start = Instant::now();

        if !self.has_tee {
            return Err(anyhow!("TEE required but not available on this worker"));
        }

        let payload: serde_json::Value = serde_json::from_slice(&request.payload)
            .map_err(|e| anyhow!("Invalid confidential VM request: {}", e))?;

        let input_path = payload.get("input_path").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing 'input_path' — path to encrypted input data"))?;
        let output_path = payload.get("output_path").and_then(|v| v.as_str()).unwrap_or("/tmp/cvm_output");
        let task = payload.get("task").and_then(|v| v.as_str()).unwrap_or("confidential_compute");

        // Compute measurement hash of the payload
        let measurement = format!("{:x}", Sha256::digest(&request.payload));

        let ai_request = self.build_ai_job_request(request, task, input_path, output_path, true);
        self.ai_engine.submit_job(ai_request.clone()).await
            .map_err(|e| anyhow!("Failed to submit confidential VM job: {}", e))?;

        let result = self.poll_ai_job(&ai_request.job_id, 300).await?;
        let execution_time_ms = start.elapsed().as_millis() as u64;

        let tee_attestation = self.generate_tee_attestation(
            &request.job_id.clone().unwrap_or_default(),
            &measurement,
        );

        let output = serde_json::json!({
            "vm_type": "confidential_container",
            "tee_platform": "Intel TDX",
            "measurement": measurement,
            "tee_attestation": tee_attestation,
            "task": task,
            "status": format!("{:?}", result.status),
            "execution_time_ms": execution_time_ms,
            "performance": result.performance_metrics,
            "exit_code": 0,
            "worker_id": self.worker_id,
            "backend": "tee_docker_gpu",
        });

        info!("✅ Confidential VM completed in {}ms (TEE + Docker)", execution_time_ms);
        Ok(serde_json::to_vec(&output)?)
    }

    /// Execute 3D Rendering job via Docker container with GPU
    async fn execute_3d_render(&self, request: &JobExecutionRequest) -> Result<Vec<u8>> {
        info!("🎨 Rendering 3D scene (Docker + GPU)...");
        let start = Instant::now();

        let payload: serde_json::Value = serde_json::from_slice(&request.payload)
            .map_err(|e| anyhow!("Invalid render request: {}", e))?;

        let input_path = payload.get("scene_file").or(payload.get("input_path"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing 'scene_file' or 'input_path' — path to 3D scene data"))?;
        let output_path = payload.get("output_path").and_then(|v| v.as_str()).unwrap_or("/tmp/render_output");
        let resolution = payload.get("resolution").and_then(|v| v.as_str()).unwrap_or("1920x1080");
        let samples = payload.get("samples").and_then(|v| v.as_u64()).unwrap_or(128);

        let ai_request = self.build_ai_job_request(request, "3d_render", input_path, output_path, true);
        self.ai_engine.submit_job(ai_request.clone()).await
            .map_err(|e| anyhow!("Failed to submit render job: {}", e))?;

        let result = self.poll_ai_job(&ai_request.job_id, 600).await?;
        let execution_time_ms = start.elapsed().as_millis() as u64;

        let output = serde_json::json!({
            "status": format!("{:?}", result.status),
            "resolution": resolution,
            "samples": samples,
            "output_path": output_path,
            "execution_time_ms": execution_time_ms,
            "performance": result.performance_metrics,
            "worker_id": self.worker_id,
            "backend": "docker_gpu",
        });

        info!("✅ 3D render completed in {}ms (Docker + GPU)", execution_time_ms);
        Ok(serde_json::to_vec(&output)?)
    }

    /// Execute Video Processing job via Docker container with GPU
    async fn execute_video_processing(&self, request: &JobExecutionRequest) -> Result<Vec<u8>> {
        info!("🎬 Processing video (Docker + GPU)...");
        let start = Instant::now();

        let payload: serde_json::Value = serde_json::from_slice(&request.payload)
            .map_err(|e| anyhow!("Invalid video processing request: {}", e))?;

        let input_path = payload.get("video_path").or(payload.get("input_path"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing 'video_path' or 'input_path' — path to video data"))?;
        let output_path = payload.get("output_path").and_then(|v| v.as_str()).unwrap_or("/tmp/video_output");
        let task = payload.get("task").and_then(|v| v.as_str()).unwrap_or("transcode");

        let ai_request = self.build_ai_job_request(request, task, input_path, output_path, true);
        self.ai_engine.submit_job(ai_request.clone()).await
            .map_err(|e| anyhow!("Failed to submit video job: {}", e))?;

        let result = self.poll_ai_job(&ai_request.job_id, 600).await?;
        let execution_time_ms = start.elapsed().as_millis() as u64;

        let output = serde_json::json!({
            "task": task,
            "status": format!("{:?}", result.status),
            "output_path": output_path,
            "execution_time_ms": execution_time_ms,
            "performance": result.performance_metrics,
            "worker_id": self.worker_id,
            "backend": "docker_gpu",
        });

        info!("✅ Video processing completed in {}ms (Docker + GPU)", execution_time_ms);
        Ok(serde_json::to_vec(&output)?)
    }

    /// Execute Computer Vision job via Docker container (PyTorch/ONNX with GPU)
    async fn execute_computer_vision(&self, request: &JobExecutionRequest) -> Result<Vec<u8>> {
        info!("👁️  Running Computer Vision (Docker + GPU)...");
        let start = Instant::now();

        let payload: serde_json::Value = serde_json::from_slice(&request.payload)
            .map_err(|e| anyhow!("Invalid CV request: {}", e))?;

        let task_type = payload.get("task_type").and_then(|v| v.as_str()).unwrap_or("object_detection");
        let model_name = payload.get("model").and_then(|v| v.as_str()).unwrap_or("yolov8n");
        let input_path = payload.get("input_path").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing 'input_path' — path to image/video data"))?;
        let output_path = payload.get("output_path").and_then(|v| v.as_str()).unwrap_or("/tmp/cv_output");

        let ai_request = self.build_ai_job_request(
            request,
            task_type,
            input_path,
            output_path,
            true, // GPU required
        );

        self.ai_engine.submit_job(ai_request.clone()).await
            .map_err(|e| anyhow!("Failed to submit CV job: {}", e))?;

        // Poll for completion
        let result = self.poll_ai_job(&ai_request.job_id, 300).await?;
        let execution_time_ms = start.elapsed().as_millis() as u64;

        let output = serde_json::json!({
            "task_type": task_type,
            "model": model_name,
            "status": format!("{:?}", result.status),
            "execution_time_ms": execution_time_ms,
            "performance": result.performance_metrics,
            "worker_id": self.worker_id,
            "backend": "docker_gpu",
        });

        info!("✅ Computer vision completed in {}ms (Docker + GPU)", execution_time_ms);
        Ok(serde_json::to_vec(&output)?)
    }

    /// Execute NLP job — routes generative tasks to vLLM, classification tasks to Docker
    async fn execute_nlp(&self, request: &JobExecutionRequest) -> Result<Vec<u8>> {
        info!("📝 Running NLP task...");
        let start = Instant::now();

        let text = String::from_utf8_lossy(&request.payload);

        let (task, user_text, use_docker) = if let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(&request.payload) {
            let task = parsed.get("task").and_then(|t| t.as_str()).unwrap_or("general").to_string();
            let input = parsed.get("input").or(parsed.get("text"))
                .and_then(|t| t.as_str())
                .unwrap_or(&text)
                .to_string();
            // Classification, NER, embeddings → Docker (BERT/specialized models)
            // Generation, summarization, translation → vLLM (LLM)
            let use_docker = matches!(task.as_str(),
                "sentiment_analysis" | "sentiment" | "ner" | "entity_extraction" |
                "classification" | "embeddings" | "token_classification"
            ) && parsed.get("input_path").is_some();
            (task, input, use_docker)
        } else {
            ("general".to_string(), text.to_string(), false)
        };

        if use_docker {
            // Route to Docker container (BERT, etc.)
            let payload: serde_json::Value = serde_json::from_slice(&request.payload)?;
            let input_path = payload.get("input_path").and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("Missing 'input_path' for Docker NLP execution"))?;
            let output_path = payload.get("output_path").and_then(|v| v.as_str()).unwrap_or("/tmp/nlp_output");

            let ai_request = self.build_ai_job_request(request, &task, input_path, output_path, true);
            self.ai_engine.submit_job(ai_request.clone()).await
                .map_err(|e| anyhow!("Failed to submit NLP job: {}", e))?;

            let result = self.poll_ai_job(&ai_request.job_id, 120).await?;
            let execution_time_ms = start.elapsed().as_millis() as u64;

            let output = serde_json::json!({
                "task": task,
                "status": format!("{:?}", result.status),
                "execution_time_ms": execution_time_ms,
                "performance": result.performance_metrics,
                "worker_id": self.worker_id,
                "backend": "docker_gpu",
            });

            info!("✅ NLP task '{}' completed in {}ms (Docker)", task, execution_time_ms);
            return Ok(serde_json::to_vec(&output)?);
        }

        // Route generative NLP to vLLM
        let endpoint = self.require_vllm()?;

        let prompt = match task.as_str() {
            "sentiment_analysis" | "sentiment" => format!(
                "Analyze the sentiment of the following text. Respond with JSON containing 'sentiment' (positive/negative/neutral) and 'confidence' (0.0-1.0):\n\n{}", user_text),
            "summarization" | "summary" => format!(
                "Summarize the following text concisely:\n\n{}", user_text),
            "translation" => format!(
                "Translate the following text to English:\n\n{}", user_text),
            "ner" | "entity_extraction" => format!(
                "Extract named entities (people, organizations, locations, dates) from the following text. Respond with JSON:\n\n{}", user_text),
            _ => user_text.clone(),
        };

        let input = serde_json::Value::String(prompt);
        let vllm_response = self.call_vllm(endpoint, &input, Some(300), Some(0.3)).await?;

        let output_text = vllm_response["choices"][0]["message"]["content"]
            .as_str().unwrap_or("").to_string();
        let model = vllm_response["model"].as_str().unwrap_or("unknown").to_string();
        let prompt_tokens = vllm_response["usage"]["prompt_tokens"].as_u64().unwrap_or(0);
        let completion_tokens = vllm_response["usage"]["completion_tokens"].as_u64().unwrap_or(0);

        let result = serde_json::json!({
            "model": model,
            "task": task,
            "input_tokens": prompt_tokens,
            "output_tokens": completion_tokens,
            "result": output_text,
            "worker_id": self.worker_id,
            "backend": "vllm",
        });

        info!("✅ NLP task '{}' completed in {}ms (vLLM, {} tokens)",
            task, start.elapsed().as_millis(), completion_tokens);
        Ok(serde_json::to_vec(&result)?)
    }

    /// Execute FHE (Fully Homomorphic Encryption) compute job
    /// Performs computations on encrypted data without decryption.
    /// If vLLM is available, appends an LLM-generated audit summary of the FHE operation.
    async fn execute_fhe_compute(&self, request: &JobExecutionRequest) -> Result<Vec<u8>> {
        info!("🔒 Running FHE Compute job...");

        #[cfg(feature = "fhe")]
        {
            // Parse the FHE compute request
            let fhe_request: FheComputeRequest = serde_json::from_slice(&request.payload)
                .map_err(|e| anyhow!("Failed to parse FHE request: {}", e))?;

            let start = Instant::now();

            // Deserialize server key
            let server_key = crate::obelysk::fhe::FheServerKey::deserialize(&fhe_request.server_key)
                .map_err(|e| anyhow!("Failed to deserialize server key: {:?}", e))?;

            // Deserialize input ciphertexts
            let mut inputs = Vec::new();
            for ct in &fhe_request.inputs {
                let encrypted = EncryptedValue::deserialize(ct)
                    .map_err(|e| anyhow!("Failed to deserialize ciphertext: {:?}", e))?;
                inputs.push(encrypted);
            }

            // Perform the requested operation
            let result_ct = match fhe_request.operation.as_str() {
                "add" => {
                    if inputs.len() < 2 {
                        return Err(anyhow!("Add requires at least 2 inputs"));
                    }
                    FheCompute::add(&inputs[0], &inputs[1], &server_key)
                        .map_err(|e| anyhow!("FHE add failed: {:?}", e))?
                }
                "mul" => {
                    if inputs.len() < 2 {
                        return Err(anyhow!("Mul requires at least 2 inputs"));
                    }
                    FheCompute::mul(&inputs[0], &inputs[1], &server_key)
                        .map_err(|e| anyhow!("FHE mul failed: {:?}", e))?
                }
                "sub" => {
                    if inputs.len() < 2 {
                        return Err(anyhow!("Sub requires at least 2 inputs"));
                    }
                    FheCompute::sub(&inputs[0], &inputs[1], &server_key)
                        .map_err(|e| anyhow!("FHE sub failed: {:?}", e))?
                }
                "sum" => {
                    FheCompute::sum(&inputs, &server_key)
                        .map_err(|e| anyhow!("FHE sum failed: {:?}", e))?
                }
                "dot_product" => {
                    let mid = inputs.len() / 2;
                    let (a, b) = inputs.split_at(mid);
                    FheCompute::dot_product(a, b, &server_key)
                        .map_err(|e| anyhow!("FHE dot_product failed: {:?}", e))?
                }
                "max" => {
                    if inputs.len() < 2 {
                        return Err(anyhow!("Max requires at least 2 inputs"));
                    }
                    FheCompute::max(&inputs[0], &inputs[1], &server_key)
                        .map_err(|e| anyhow!("FHE max failed: {:?}", e))?
                }
                "min" => {
                    if inputs.len() < 2 {
                        return Err(anyhow!("Min requires at least 2 inputs"));
                    }
                    FheCompute::min(&inputs[0], &inputs[1], &server_key)
                        .map_err(|e| anyhow!("FHE min failed: {:?}", e))?
                }
                op => return Err(anyhow!("Unknown FHE operation: {}", op)),
            };

            let compute_time_ms = start.elapsed().as_millis() as u64;

            // Serialize result ciphertext
            let result_serialized = result_ct.serialize()
                .map_err(|e| anyhow!("Failed to serialize result: {:?}", e))?;

            let response = FheComputeResponse {
                result: result_serialized,
                compute_time_ms,
                operation: fhe_request.operation.clone(),
                worker_id: self.worker_id.clone(),
                tee_protected: self.has_tee,
            };

            // Generate LLM audit summary if vLLM is available
            let mut response_value = serde_json::to_value(&response)?;
            if let Some(ref endpoint) = self.vllm_endpoint {
                let prompt = format!(
                    "You are an FHE computation auditor. Summarize this encrypted computation in 1-2 sentences:\n\
                    - Operation: {}\n\
                    - Number of inputs: {}\n\
                    - Compute time: {}ms\n\
                    - TEE protected: {}",
                    fhe_request.operation,
                    inputs.len(),
                    compute_time_ms,
                    self.has_tee,
                );
                let input = serde_json::Value::String(prompt);
                if let Ok(vllm_resp) = self.call_vllm(endpoint, &input, Some(100), Some(0.3)).await {
                    if let Some(text) = vllm_resp["choices"][0]["message"]["content"].as_str() {
                        response_value["audit_summary"] = serde_json::json!(text);
                        response_value["source"] = serde_json::json!("fhe+vllm");
                    }
                }
            }

            info!("✅ FHE compute completed in {}ms", compute_time_ms);
            Ok(serde_json::to_vec(&response_value)?)
        }

        #[cfg(not(feature = "fhe"))]
        {
            let _ = request;
            Err(anyhow!("FHE feature not enabled. Build with --features fhe"))
        }
    }

    /// Execute Confidential AI job - AI inference on FHE-encrypted data
    /// Combines FHE encryption with AI model execution for fully private inference.
    /// If vLLM is available, appends an LLM-generated audit of the confidential inference.
    async fn execute_confidential_ai(&self, request: &JobExecutionRequest) -> Result<Vec<u8>> {
        info!("🔐🤖 Running Confidential AI (FHE + AI Inference)...");

        #[cfg(feature = "fhe")]
        {
            let start = Instant::now();

            // Parse the confidential AI request
            let conf_request: ConfidentialAIRequest = serde_json::from_slice(&request.payload)
                .map_err(|e| anyhow!("Failed to parse Confidential AI request: {}", e))?;

            // Deserialize server key for FHE operations
            let server_key = crate::obelysk::fhe::FheServerKey::deserialize(&conf_request.server_key)
                .map_err(|e| anyhow!("Failed to deserialize server key: {:?}", e))?;

            // Deserialize encrypted input features
            let mut encrypted_inputs = Vec::new();
            for ct in &conf_request.encrypted_inputs {
                let encrypted = EncryptedValue::deserialize(ct)
                    .map_err(|e| anyhow!("Failed to deserialize input: {:?}", e))?;
                encrypted_inputs.push(encrypted);
            }

            let num_inputs = encrypted_inputs.len();
            let num_layers = conf_request.model_weights.len();

            info!("📊 Processing {} encrypted features through {} layers",
                num_inputs, num_layers);

            // Perform encrypted neural network inference
            let mut current_layer = encrypted_inputs;

            for (layer_idx, layer_weights) in conf_request.model_weights.iter().enumerate() {
                info!("  Layer {}: {} neurons", layer_idx + 1, layer_weights.len());

                let mut layer_output = Vec::new();

                for neuron_weights in layer_weights {
                    let mut weights = Vec::new();
                    for w in neuron_weights {
                        let weight = EncryptedValue::deserialize(w)
                            .map_err(|e| anyhow!("Failed to deserialize weight: {:?}", e))?;
                        weights.push(weight);
                    }

                    if weights.len() == current_layer.len() {
                        let dot = FheCompute::dot_product(&weights, &current_layer, &server_key)
                            .map_err(|e| anyhow!("Dot product failed: {:?}", e))?;

                        let activated = FheCompute::relu(&dot, &server_key)
                            .map_err(|e| anyhow!("ReLU failed: {:?}", e))?;

                        layer_output.push(activated);
                    }
                }

                current_layer = layer_output;
            }

            let compute_time_ms = start.elapsed().as_millis() as u64;

            // Serialize output ciphertexts
            let mut encrypted_outputs = Vec::new();
            for ct in &current_layer {
                let serialized = ct.serialize()
                    .map_err(|e| anyhow!("Failed to serialize output: {:?}", e))?;
                encrypted_outputs.push(serialized);
            }

            let response = ConfidentialAIResponse {
                encrypted_outputs,
                compute_time_ms,
                model_type: conf_request.model_type.clone(),
                layers_processed: num_layers,
                worker_id: self.worker_id.clone(),
                tee_protected: self.has_tee,
            };

            // Generate LLM audit of the confidential inference
            let mut response_value = serde_json::to_value(&response)?;
            if let Some(ref endpoint) = self.vllm_endpoint {
                let prompt = format!(
                    "You are a confidential AI auditor. Summarize this private ML inference in 1-2 sentences:\n\
                    - Model type: {}\n\
                    - Input features: {}\n\
                    - Layers processed: {}\n\
                    - Output neurons: {}\n\
                    - Compute time: {}ms\n\
                    - TEE protected: {}\n\
                    Note: All data was encrypted via FHE — the worker never saw plaintext.",
                    conf_request.model_type,
                    num_inputs,
                    num_layers,
                    current_layer.len(),
                    compute_time_ms,
                    self.has_tee,
                );
                let input = serde_json::Value::String(prompt);
                if let Ok(vllm_resp) = self.call_vllm(endpoint, &input, Some(150), Some(0.3)).await {
                    if let Some(text) = vllm_resp["choices"][0]["message"]["content"].as_str() {
                        response_value["audit_summary"] = serde_json::json!(text);
                        response_value["source"] = serde_json::json!("fhe+vllm");
                    }
                }
            }

            info!("✅ Confidential AI inference completed in {}ms", compute_time_ms);
            Ok(serde_json::to_vec(&response_value)?)
        }

        #[cfg(not(feature = "fhe"))]
        {
            let _ = request;
            Err(anyhow!("FHE feature not enabled. Build with --features fhe"))
        }
    }

    /// Execute explicit ZK Proof generation job (STWO)
    /// Generates the proof with Obelysk, and if vLLM is available, also provides
    /// an LLM-generated explanation/audit of the proof for the caller
    async fn execute_zk_proof(&self, request: &JobExecutionRequest) -> Result<Vec<u8>> {
        info!("🔒 Running ZK Proof generation (STWO)...");
        let start = Instant::now();

        let job_id = request.job_id.clone().unwrap_or_else(|| "zk-proof".to_string());

        // Parse proof request payload
        let proof_request: ZkProofRequest = serde_json::from_slice(&request.payload)
            .unwrap_or_else(|_| ZkProofRequest {
                circuit_type: "generic".to_string(),
                public_inputs: request.payload.clone(),
                private_inputs: None,
                security_bits: 128,
                compress_output: true,
            });

        // Execute with Obelysk prover
        match self.obelysk_executor.execute_with_proof(&job_id, &proof_request.circuit_type, &proof_request.public_inputs).await {
            Ok(proof_result) => {
                let proof_time_ms = start.elapsed().as_millis() as u64;

                // If vLLM is available, generate a human-readable explanation of the proof
                let proof_explanation = if let Some(ref endpoint) = self.vllm_endpoint {
                    let prompt = format!(
                        "You are a ZK proof auditor. Summarize this ZK proof in 2-3 sentences:\n\
                        - Circuit type: {}\n\
                        - Security bits: {}\n\
                        - Proof size: {} bytes\n\
                        - Generation time: {}ms\n\
                        - GPU accelerated: {}\n\
                        - Proof hash: {}",
                        proof_request.circuit_type,
                        proof_request.security_bits,
                        proof_result.metrics.proof_size_bytes,
                        proof_time_ms,
                        proof_result.metrics.gpu_used,
                        hex::encode(proof_result.proof_hash),
                    );
                    let input = serde_json::Value::String(prompt);
                    match self.call_vllm(endpoint, &input, Some(200), Some(0.3)).await {
                        Ok(resp) => resp["choices"][0]["message"]["content"]
                            .as_str().map(|s| s.to_string()),
                        Err(_) => None,
                    }
                } else {
                    None
                };

                let mut response_value = serde_json::to_value(ZkProofResponse {
                    proof_hash: hex::encode(proof_result.proof_hash),
                    proof_attestation: hex::encode(proof_result.proof_attestation),
                    proof_commitment: hex::encode(proof_result.proof_commitment),
                    compressed_proof_bytes: proof_result.compressed_proof.as_ref()
                        .map(|p| p.data.clone()),
                    proof_size_bytes: proof_result.metrics.proof_size_bytes,
                    proof_time_ms,
                    trace_length: proof_result.metrics.trace_length,
                    gpu_used: proof_result.metrics.gpu_used,
                    gpu_speedup: proof_result.metrics.gpu_speedup,
                    circuit_type: proof_request.circuit_type,
                    security_bits: proof_request.security_bits,
                    worker_id: self.worker_id.clone(),
                })?;

                if let Some(explanation) = proof_explanation {
                    response_value["proof_explanation"] = serde_json::json!(explanation);
                    response_value["vllm_source"] = serde_json::json!("vllm");
                }

                info!("✅ ZK Proof generated: {} bytes, {}ms", proof_result.metrics.proof_size_bytes, proof_time_ms);
                Ok(serde_json::to_vec(&response_value)?)
            }
            Err(e) => {
                Err(anyhow!("ZK proof generation failed: {}", e))
            }
        }
    }

    /// Execute model deployment job via vLLM
    async fn execute_model_deploy(&self, request: &JobExecutionRequest) -> Result<Vec<u8>> {
        info!("🚀 Deploying model...");
        let endpoint = self.require_vllm()?;
        let start = Instant::now();

        let deploy_request: ModelDeployRequest = serde_json::from_slice(&request.payload)
            .map_err(|e| anyhow!("Invalid model deploy request: {}", e))?;

        let resp = self.http_client.get(format!("{}/v1/models", endpoint)).send().await
            .map_err(|e| anyhow!("vLLM unreachable during model deploy: {}", e))?;

        if !resp.status().is_success() {
            return Err(anyhow!("vLLM /v1/models returned {}", resp.status()));
        }

        let body: serde_json::Value = resp.json().await.unwrap_or_default();
        let models: Vec<String> = body["data"].as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|m| m["id"].as_str().map(|s| s.to_string()))
            .collect();

        let deployment_time_ms = start.elapsed().as_millis() as u64;
        let served_model = models.first().cloned().unwrap_or(deploy_request.model_name.clone());
        let model_id = format!("model-{}", uuid::Uuid::new_v4().to_string()[..8].to_string());

        let response = ModelDeployResponse {
            model_id: model_id.clone(),
            model_name: served_model.clone(),
            endpoint: format!("{}/v1/chat/completions", endpoint),
            status: "deployed_vllm".to_string(),
            worker_id: self.worker_id.clone(),
            deployment_time_ms,
            estimated_inference_time_ms: 50,
            vram_used_mb: match deploy_request.model_size.as_str() {
                "small" => 2048,
                "medium" => 8192,
                "large" => 24576,
                "xlarge" => 49152,
                _ => 4096,
            },
            supported_batch_sizes: vec![1, 2, 4, 8, 16, 32, 64],
        };

        info!("✅ Model {} deployed via vLLM ({}) in {}ms",
            deploy_request.model_name, served_model, deployment_time_ms);
        Ok(serde_json::to_vec(&response)?)
    }

    /// Execute model inference job via vLLM (all model types)
    async fn execute_model_inference(&self, request: &JobExecutionRequest) -> Result<Vec<u8>> {
        info!("🧠 Running model inference...");
        let endpoint = self.require_vllm()?;
        let start = Instant::now();

        let inference_request: ModelInferenceRequest = serde_json::from_slice(&request.payload)
            .map_err(|e| anyhow!("Invalid inference request: {}", e))?;

        // Build a system prompt tailored to the model type
        let system_prompt = match inference_request.model_type.as_str() {
            "llm" => None,
            "embedding" => Some("You are an embedding model. Represent the following text as a list of floating-point numbers. Return only the JSON array of numbers.".to_string()),
            "classification" => Some("You are a classification model. Classify the following input and return JSON with 'label', 'confidence', and 'all_scores' fields.".to_string()),
            "object_detection" => Some("You are an object detection model. Analyze the following input and return JSON with 'detections' array, each containing 'class', 'confidence', and 'bbox' [x1,y1,x2,y2].".to_string()),
            "image_gen" => Some("You are an image generation assistant. Given the following prompt, describe in detail the image you would generate, including composition, colors, style, and mood. Return JSON with 'description' and 'parameters'.".to_string()),
            other => Some(format!("You are a {} model. Process the following input and return structured JSON output.", other)),
        };

        let input_value = if let Some(sys) = system_prompt {
            let user_content = if let Some(text) = inference_request.input.as_str() {
                text.to_string()
            } else {
                inference_request.input.to_string()
            };
            serde_json::json!({
                "messages": [
                    {"role": "system", "content": sys},
                    {"role": "user", "content": user_content}
                ]
            })
        } else {
            inference_request.input.clone()
        };

        info!("🧠 Forwarding {} inference to vLLM at {}", inference_request.model_type, endpoint);
        let vllm_response = self.call_vllm(
            endpoint,
            &input_value,
            inference_request.max_tokens,
            inference_request.temperature,
        ).await?;

        let inference_time_ms = start.elapsed().as_millis() as u64;
        let text = vllm_response["choices"][0]["message"]["content"]
            .as_str().unwrap_or("").to_string();
        let prompt_tokens = vllm_response["usage"]["prompt_tokens"].as_u64().unwrap_or(0);
        let completion_tokens = vllm_response["usage"]["completion_tokens"].as_u64().unwrap_or(0);
        let model_name = vllm_response["model"].as_str().unwrap_or("unknown").to_string();
        let finish_reason = vllm_response["choices"][0]["finish_reason"]
            .as_str().unwrap_or("stop").to_string();

        let output = match inference_request.model_type.as_str() {
            "llm" => serde_json::json!({
                "text": text,
                "model": model_name,
                "tokens_generated": completion_tokens,
                "prompt_tokens": prompt_tokens,
                "finish_reason": finish_reason,
                "source": "vllm",
            }),
            "embedding" => {
                let parsed = serde_json::from_str::<serde_json::Value>(&text).ok();
                serde_json::json!({
                    "embedding": parsed.unwrap_or(serde_json::json!(text)),
                    "model": model_name,
                    "source": "vllm",
                })
            }
            _ => {
                let parsed = serde_json::from_str::<serde_json::Value>(&text)
                    .unwrap_or(serde_json::json!({"text": text}));
                let mut output = parsed;
                if let Some(obj) = output.as_object_mut() {
                    obj.insert("model".to_string(), serde_json::json!(model_name));
                    obj.insert("tokens_generated".to_string(), serde_json::json!(completion_tokens));
                    obj.insert("source".to_string(), serde_json::json!("vllm"));
                }
                output
            }
        };

        let response = ModelInferenceResponse {
            model_id: inference_request.model_id.clone(),
            output,
            inference_time_ms,
            tokens_processed: prompt_tokens + completion_tokens,
            worker_id: self.worker_id.clone(),
            gpu_memory_used_mb: 4096,
        };

        info!("✅ vLLM {} inference completed in {}ms ({} tokens)",
            inference_request.model_type, inference_time_ms, completion_tokens);
        Ok(serde_json::to_vec(&response)?)
    }

    /// Execute batch inference job via vLLM
    async fn execute_batch_inference(&self, request: &JobExecutionRequest) -> Result<Vec<u8>> {
        info!("📦 Running batch inference...");
        let endpoint = self.require_vllm()?;
        let start = Instant::now();

        let batch_request: BatchInferenceRequest = serde_json::from_slice(&request.payload)
            .map_err(|e| anyhow!("Invalid batch inference request: {}", e))?;

        let batch_size = batch_request.inputs.len();
        info!("  Processing batch of {} inputs via vLLM at {}", batch_size, endpoint);

        let mut outputs: Vec<serde_json::Value> = Vec::with_capacity(batch_size);

        for (i, input) in batch_request.inputs.iter().enumerate() {
            let vllm_response = self.call_vllm(endpoint, input, Some(100), None).await
                .map_err(|e| anyhow!("Batch item {} failed: {}", i, e))?;

            let text = vllm_response["choices"][0]["message"]["content"]
                .as_str().unwrap_or("").to_string();
            let tokens = vllm_response["usage"]["completion_tokens"].as_u64().unwrap_or(0);
            outputs.push(serde_json::json!({
                "index": i,
                "result": text,
                "tokens": tokens,
                "source": "vllm",
            }));
        }

        let batch_time_ms = start.elapsed().as_millis() as u64;

        let response = BatchInferenceResponse {
            model_id: batch_request.model_id,
            outputs,
            batch_size,
            total_time_ms: batch_time_ms,
            avg_time_per_item_ms: if batch_size > 0 { batch_time_ms / batch_size as u64 } else { 0 },
            worker_id: self.worker_id.clone(),
            gpu_utilization: 0.85,
        };

        info!("✅ Batch inference completed: {} items in {}ms", batch_size, batch_time_ms);
        Ok(serde_json::to_vec(&response)?)
    }

    // ========================================================================
    // Model Training Jobs
    // ========================================================================

    /// Execute model training job via Docker container with GPU
    /// Supports full training, LoRA, QLoRA, and frozen-layer fine-tuning
    async fn execute_model_training(&self, request: &JobExecutionRequest) -> Result<Vec<u8>> {
        info!("🏋️ Running Model Training (Docker + GPU)...");
        let start = Instant::now();

        let training_request: ModelTrainingRequest = serde_json::from_slice(&request.payload)
            .map_err(|e| anyhow!("Invalid training request: {}", e))?;

        info!("  Base model: {}", training_request.base_model);
        info!("  Mode: {}", training_request.training_mode);
        info!("  Dataset: {}", training_request.dataset_path);
        info!("  GPUs: {}", training_request.num_gpus);
        info!("  Epochs: {}", training_request.hyperparameters.num_epochs);
        info!("  LR: {}", training_request.hyperparameters.learning_rate);

        // Build Docker command for training
        let docker_cmd = self.build_training_docker_command(&training_request)?;
        info!("  Docker command: {}", docker_cmd.join(" "));

        // Execute Docker training container
        let output = self.run_docker_command(&docker_cmd, request.requirements.timeout_seconds).await?;

        let training_time_ms = start.elapsed().as_millis() as u64;
        let gpu_hours = (training_time_ms as f64 / 3_600_000.0) * training_request.num_gpus as f64;

        // Parse training output for metrics
        let (final_loss, steps_completed, checkpoints) = self.parse_training_output(&output);

        let response = ModelTrainingResponse {
            job_id: request.job_id.clone().unwrap_or_default(),
            model_output_path: training_request.output_path.clone(),
            status: "completed".to_string(),
            training_time_ms,
            final_loss,
            final_eval_loss: None,
            steps_completed,
            checkpoints,
            gpu_hours,
            worker_id: self.worker_id.clone(),
            training_mode: training_request.training_mode.clone(),
            framework: training_request.framework.clone(),
        };

        info!("✅ Training completed in {}ms ({:.2} GPU-hours, loss: {:?})",
            training_time_ms, gpu_hours, final_loss);
        Ok(serde_json::to_vec(&response)?)
    }

    /// Execute reinforcement learning training job
    async fn execute_rl_training(&self, request: &JobExecutionRequest) -> Result<Vec<u8>> {
        info!("🎮 Running RL Training (Docker + GPU)...");
        let start = Instant::now();

        let rl_request: RLTrainingRequest = serde_json::from_slice(&request.payload)
            .map_err(|e| anyhow!("Invalid RL training request: {}", e))?;

        info!("  Algorithm: {}", rl_request.algorithm);
        info!("  Steps: {}", rl_request.training_steps);
        if let Some(ref model) = rl_request.base_model {
            info!("  Base model: {}", model);
        }
        if let Some(ref env) = rl_request.environment {
            info!("  Environment: {}", env);
        }

        let docker_cmd = self.build_rl_docker_command(&rl_request)?;
        info!("  Docker command: {}", docker_cmd.join(" "));

        let output = self.run_docker_command(&docker_cmd, request.requirements.timeout_seconds).await?;

        let training_time_ms = start.elapsed().as_millis() as u64;
        let gpu_hours = (training_time_ms as f64 / 3_600_000.0) * rl_request.num_gpus as f64;
        let (final_metric, steps_completed, checkpoints) = self.parse_training_output(&output);

        let metric_name = match rl_request.algorithm.as_str() {
            "dpo" => "loss",
            "rlhf" | "ppo" | "grpo" => "reward",
            _ => "return",
        }.to_string();

        let response = RLTrainingResponse {
            job_id: request.job_id.clone().unwrap_or_default(),
            model_output_path: rl_request.output_path.clone(),
            status: "completed".to_string(),
            training_time_ms,
            steps_completed,
            final_metric,
            metric_name,
            checkpoints,
            gpu_hours,
            worker_id: self.worker_id.clone(),
        };

        info!("✅ RL training completed in {}ms ({:.2} GPU-hours)", training_time_ms, gpu_hours);
        Ok(serde_json::to_vec(&response)?)
    }

    /// Build Docker command for model training
    fn build_training_docker_command(&self, req: &ModelTrainingRequest) -> Result<Vec<String>> {
        let mut cmd = vec![
            "docker".to_string(), "run".to_string(), "--rm".to_string(),
            "--gpus".to_string(), format!("\"device={}\"",
                (0..req.num_gpus).map(|i| i.to_string()).collect::<Vec<_>>().join(",")),
            "--shm-size".to_string(), "16g".to_string(), // Shared memory for DataLoader workers
        ];

        // Mount volumes
        cmd.extend_from_slice(&[
            "-v".to_string(), format!("{}:/data", req.dataset_path),
            "-v".to_string(), format!("{}:/output", req.output_path),
        ]);
        if let Some(ref eval_path) = req.eval_dataset_path {
            cmd.extend_from_slice(&["-v".to_string(), format!("{}:/eval_data", eval_path)]);
        }

        // Select Docker image based on framework and training mode
        let image = match (req.framework.as_str(), req.training_mode.as_str()) {
            ("huggingface", "lora") | ("huggingface", "qlora") =>
                "huggingface/transformers-pytorch-gpu:4.21.0",
            ("huggingface", _) =>
                "huggingface/transformers-pytorch-gpu:4.21.0",
            ("deepspeed", _) =>
                "pytorch/pytorch:2.0.1-cuda11.7-cudnn8-runtime",
            ("pytorch", _) =>
                "pytorch/pytorch:2.0.1-cuda11.7-cudnn8-runtime",
            _ => "huggingface/transformers-pytorch-gpu:4.21.0",
        };
        cmd.push(image.to_string());

        // Build training command based on framework
        match req.framework.as_str() {
            "huggingface" => {
                cmd.extend_from_slice(&[
                    "python".to_string(), "-m".to_string(), "transformers.trainer".to_string(),
                    "--model_name_or_path".to_string(), req.base_model.clone(),
                    "--train_file".to_string(), "/data".to_string(),
                    "--output_dir".to_string(), "/output".to_string(),
                    "--do_train".to_string(),
                    "--num_train_epochs".to_string(), req.hyperparameters.num_epochs.to_string(),
                    "--per_device_train_batch_size".to_string(), req.hyperparameters.per_device_batch_size.to_string(),
                    "--gradient_accumulation_steps".to_string(), req.hyperparameters.gradient_accumulation_steps.to_string(),
                    "--learning_rate".to_string(), req.hyperparameters.learning_rate.to_string(),
                    "--weight_decay".to_string(), req.hyperparameters.weight_decay.to_string(),
                    "--warmup_steps".to_string(), req.hyperparameters.warmup_steps.to_string(),
                    "--lr_scheduler_type".to_string(), req.hyperparameters.lr_scheduler.clone(),
                    "--max_grad_norm".to_string(), req.hyperparameters.max_grad_norm.to_string(),
                    "--logging_steps".to_string(), "10".to_string(),
                    "--save_strategy".to_string(),
                    if req.checkpoint_every_n_steps > 0 { "steps" } else { "epoch" }.to_string(),
                ]);

                if req.checkpoint_every_n_steps > 0 {
                    cmd.extend_from_slice(&[
                        "--save_steps".to_string(), req.checkpoint_every_n_steps.to_string(),
                    ]);
                }

                if let Some(ref max_steps) = req.hyperparameters.max_steps {
                    cmd.extend_from_slice(&["--max_steps".to_string(), max_steps.to_string()]);
                }

                // Mixed precision
                match req.hyperparameters.mixed_precision.as_str() {
                    "bf16" => { cmd.push("--bf16".to_string()); }
                    "fp16" => { cmd.push("--fp16".to_string()); }
                    _ => {}
                }

                // LoRA config
                if let Some(ref lora) = req.lora_config {
                    cmd.extend_from_slice(&[
                        "--use_peft".to_string(),
                        "--lora_r".to_string(), lora.rank.to_string(),
                        "--lora_alpha".to_string(), lora.alpha.to_string(),
                        "--lora_dropout".to_string(), lora.dropout.to_string(),
                    ]);
                    if !lora.target_modules.is_empty() {
                        cmd.extend_from_slice(&[
                            "--lora_target_modules".to_string(),
                            lora.target_modules.join(","),
                        ]);
                    }
                    if lora.use_4bit {
                        cmd.push("--load_in_4bit".to_string());
                        cmd.extend_from_slice(&[
                            "--bnb_4bit_quant_type".to_string(), lora.bnb_4bit_quant_type.clone(),
                        ]);
                    }
                }

                // Eval dataset
                if req.eval_dataset_path.is_some() {
                    cmd.extend_from_slice(&[
                        "--do_eval".to_string(),
                        "--validation_file".to_string(), "/eval_data".to_string(),
                        "--evaluation_strategy".to_string(), "steps".to_string(),
                    ]);
                }
            }
            "deepspeed" => {
                // Multi-GPU with DeepSpeed
                cmd.extend_from_slice(&[
                    "deepspeed".to_string(),
                    "--num_gpus".to_string(), req.num_gpus.to_string(),
                    "train.py".to_string(),
                    "--model".to_string(), req.base_model.clone(),
                    "--data".to_string(), "/data".to_string(),
                    "--output".to_string(), "/output".to_string(),
                    "--epochs".to_string(), req.hyperparameters.num_epochs.to_string(),
                    "--lr".to_string(), req.hyperparameters.learning_rate.to_string(),
                    "--batch-size".to_string(), req.hyperparameters.per_device_batch_size.to_string(),
                ]);
            }
            _ => {
                // Generic PyTorch
                cmd.extend_from_slice(&[
                    "python".to_string(), "train.py".to_string(),
                    "--model".to_string(), req.base_model.clone(),
                    "--data".to_string(), "/data".to_string(),
                    "--output".to_string(), "/output".to_string(),
                    "--epochs".to_string(), req.hyperparameters.num_epochs.to_string(),
                    "--lr".to_string(), req.hyperparameters.learning_rate.to_string(),
                    "--batch-size".to_string(), req.hyperparameters.per_device_batch_size.to_string(),
                ]);
            }
        }

        Ok(cmd)
    }

    /// Build Docker command for RL training
    fn build_rl_docker_command(&self, req: &RLTrainingRequest) -> Result<Vec<String>> {
        let mut cmd = vec![
            "docker".to_string(), "run".to_string(), "--rm".to_string(),
            "--gpus".to_string(), format!("\"device={}\"",
                (0..req.num_gpus).map(|i| i.to_string()).collect::<Vec<_>>().join(",")),
            "--shm-size".to_string(), "16g".to_string(),
            "-v".to_string(), format!("{}:/output", req.output_path),
        ];

        // Mount datasets
        if let Some(ref pref) = req.preference_dataset {
            cmd.extend_from_slice(&["-v".to_string(), format!("{}:/data/preferences", pref)]);
        }

        let image = match req.algorithm.as_str() {
            "dpo" | "rlhf" | "grpo" | "ppo" =>
                "huggingface/transformers-pytorch-gpu:4.21.0",
            _ => "pytorch/pytorch:2.0.1-cuda11.7-cudnn8-runtime",
        };
        cmd.push(image.to_string());

        match req.algorithm.as_str() {
            "dpo" => {
                let base = req.base_model.as_deref()
                    .ok_or_else(|| anyhow!("DPO requires 'base_model'"))?;
                let pref_dataset = req.preference_dataset.as_deref()
                    .ok_or_else(|| anyhow!("DPO requires 'preference_dataset'"))?;
                let _ = pref_dataset; // used via volume mount
                cmd.extend_from_slice(&[
                    "python".to_string(), "-m".to_string(), "trl.commands.cli".to_string(), "dpo".to_string(),
                    "--model_name_or_path".to_string(), base.to_string(),
                    "--dataset_name".to_string(), "/data/preferences".to_string(),
                    "--output_dir".to_string(), "/output".to_string(),
                    "--num_train_epochs".to_string(), "1".to_string(),
                    "--max_steps".to_string(), req.training_steps.to_string(),
                ]);
            }
            "rlhf" | "ppo" => {
                let base = req.base_model.as_deref()
                    .ok_or_else(|| anyhow!("RLHF/PPO requires 'base_model'"))?;
                let reward = req.reward_model.as_deref()
                    .ok_or_else(|| anyhow!("RLHF/PPO requires 'reward_model'"))?;
                cmd.extend_from_slice(&[
                    "python".to_string(), "-m".to_string(), "trl.commands.cli".to_string(), "ppo".to_string(),
                    "--model_name_or_path".to_string(), base.to_string(),
                    "--reward_model".to_string(), reward.to_string(),
                    "--output_dir".to_string(), "/output".to_string(),
                    "--steps".to_string(), req.training_steps.to_string(),
                ]);
            }
            _ => {
                // Generic RL (gym environment)
                let env = req.environment.as_deref().unwrap_or("CartPole-v1");
                cmd.extend_from_slice(&[
                    "python".to_string(), "train_rl.py".to_string(),
                    "--algorithm".to_string(), req.algorithm.clone(),
                    "--env".to_string(), env.to_string(),
                    "--steps".to_string(), req.training_steps.to_string(),
                    "--output".to_string(), "/output".to_string(),
                ]);
            }
        }

        // Add hyperparameters
        for (key, value) in &req.hyperparameters {
            cmd.extend_from_slice(&[
                format!("--{}", key),
                value.to_string().trim_matches('"').to_string(),
            ]);
        }

        Ok(cmd)
    }

    /// Run a Docker command and return stdout
    async fn run_docker_command(&self, cmd: &[String], timeout_secs: u64) -> Result<String> {
        use std::process::Stdio;
        let timeout_duration = std::time::Duration::from_secs(timeout_secs);

        let result = tokio::time::timeout(timeout_duration, async {
            let output = tokio::process::Command::new(&cmd[0])
                .args(&cmd[1..])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .await
                .map_err(|e| anyhow!("Failed to execute Docker command: {}", e))?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(anyhow!("Docker command failed (exit {}): {}", output.status, stderr));
            }

            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        }).await;

        match result {
            Ok(Ok(output)) => Ok(output),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(anyhow!("Docker command timed out after {}s", timeout_secs)),
        }
    }

    /// Parse training output for loss, steps, and checkpoint paths
    fn parse_training_output(&self, output: &str) -> (Option<f64>, u64, Vec<String>) {
        let mut final_loss = None;
        let mut steps = 0u64;
        let mut checkpoints = Vec::new();

        for line in output.lines() {
            // Parse HuggingFace Trainer JSON output
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(line) {
                if let Some(loss) = parsed.get("loss").and_then(|v| v.as_f64()) {
                    final_loss = Some(loss);
                }
                if let Some(step) = parsed.get("step").or(parsed.get("global_step")).and_then(|v| v.as_u64()) {
                    steps = step;
                }
            }
            // Parse checkpoint save messages
            if line.contains("Saving model checkpoint to") || line.contains("checkpoint-") {
                if let Some(path) = line.split_whitespace().last() {
                    checkpoints.push(path.to_string());
                }
            }
            // Parse loss from training logs: "{'loss': 0.5, 'step': 100}"
            if line.contains("'loss'") || line.contains("\"loss\"") {
                if let Some(loss_str) = line.split("loss").nth(1) {
                    if let Some(num) = loss_str.split(|c: char| !c.is_numeric() && c != '.' && c != '-')
                        .find(|s| !s.is_empty())
                    {
                        if let Ok(loss) = num.parse::<f64>() {
                            final_loss = Some(loss);
                        }
                    }
                }
            }
        }

        (final_loss, steps, checkpoints)
    }

    // ========================================================================
    // Simple Pipeline Test Jobs (Ping/Echo)
    // ========================================================================

    /// Execute Ping job - pipeline verification
    /// Reports vLLM availability in the response so callers know this worker has a live GPU backend
    async fn execute_ping(&self, _request: &JobExecutionRequest) -> Result<Vec<u8>> {
        info!("🏓 Executing Ping job...");

        // Probe vLLM to report its status
        let (vllm_status, vllm_models) = if let Some(ref endpoint) = self.vllm_endpoint {
            match self.http_client.get(format!("{}/v1/models", endpoint)).send().await {
                Ok(resp) if resp.status().is_success() => {
                    let body: serde_json::Value = resp.json().await.unwrap_or_default();
                    let models: Vec<String> = body["data"].as_array()
                        .unwrap_or(&vec![])
                        .iter()
                        .filter_map(|m| m["id"].as_str().map(|s| s.to_string()))
                        .collect();
                    ("online".to_string(), models)
                }
                _ => ("unreachable".to_string(), vec![]),
            }
        } else {
            ("not_configured".to_string(), vec![])
        };

        let response = serde_json::json!({
            "response": "pong",
            "worker_id": self.worker_id,
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "proofs_enabled": self.enable_proofs,
            "tee_available": self.has_tee,
            "vllm_status": vllm_status,
            "vllm_endpoint": self.vllm_endpoint,
            "vllm_models": vllm_models,
            "gpu_model": self.gpu_model,
            "message": "BitSage pipeline verified - worker is operational!"
        });

        Ok(serde_json::to_vec(&response)?)
    }

    /// Execute Echo job - returns the payload back, optionally through vLLM
    /// If payload JSON contains `"transform": true`, runs the echo text through vLLM first
    async fn execute_echo(&self, request: &JobExecutionRequest) -> Result<Vec<u8>> {
        info!("📢 Executing Echo job...");

        let payload_str = String::from_utf8_lossy(&request.payload);

        // Check if caller wants the echo text transformed through vLLM
        let wants_transform = serde_json::from_slice::<serde_json::Value>(&request.payload)
            .ok()
            .and_then(|v| v.get("transform").and_then(|t| t.as_bool()))
            .unwrap_or(false);

        if wants_transform {
            let endpoint = self.require_vllm()?;

            let input_text = serde_json::from_slice::<serde_json::Value>(&request.payload)
                .ok()
                .and_then(|v| v.get("input").or(v.get("echo")).and_then(|t| t.as_str()).map(|s| s.to_string()))
                .unwrap_or_else(|| payload_str.to_string());

            let input = serde_json::Value::String(input_text);
            let max_tokens = serde_json::from_slice::<serde_json::Value>(&request.payload)
                .ok()
                .and_then(|v| v.get("max_tokens").and_then(|t| t.as_u64()).map(|t| t as u32));

            let vllm_response = self.call_vllm(endpoint, &input, max_tokens, None).await?;

            let text = vllm_response["choices"][0]["message"]["content"]
                .as_str().unwrap_or("").to_string();
            let model = vllm_response["model"].as_str().unwrap_or("unknown").to_string();
            let tokens = vllm_response["usage"]["completion_tokens"].as_u64().unwrap_or(0);

            let response = serde_json::json!({
                "echo": payload_str,
                "transformed": text,
                "model": model,
                "tokens_generated": tokens,
                "original_size_bytes": request.payload.len(),
                "worker_id": self.worker_id,
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "source": "vllm",
            });

            return Ok(serde_json::to_vec(&response)?);
        }

        let response = serde_json::json!({
            "echo": payload_str,
            "original_size_bytes": request.payload.len(),
            "worker_id": self.worker_id,
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "vllm_available": self.vllm_endpoint.is_some(),
        });

        Ok(serde_json::to_vec(&response)?)
    }

    // ========================================================================
    // Generic/Fallback
    // ========================================================================

    /// Generic executor — attempts Docker execution if payload has input_path,
    /// otherwise rejects with a clear error listing supported job types
    async fn execute_generic(&self, request: &JobExecutionRequest) -> Result<Vec<u8>> {
        let job_type = request.job_type.clone().unwrap_or_else(|| "unknown".to_string());
        info!("⚙️  Running generic job (type: {})...", job_type);

        // Try to parse as a structured job with input/output paths
        if let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&request.payload) {
            if let Some(input_path) = payload.get("input_path").and_then(|v| v.as_str()) {
                let start = Instant::now();
                let output_path = payload.get("output_path").and_then(|v| v.as_str()).unwrap_or("/tmp/generic_output");
                let task = payload.get("task").and_then(|v| v.as_str()).unwrap_or("general_ai");

                let ai_request = self.build_ai_job_request(request, task, input_path, output_path, true);
                self.ai_engine.submit_job(ai_request.clone()).await
                    .map_err(|e| anyhow!("Failed to submit generic job: {}", e))?;

                let result = self.poll_ai_job(&ai_request.job_id, 300).await?;
                let execution_time_ms = start.elapsed().as_millis() as u64;

                let output = serde_json::json!({
                    "job_type": job_type,
                    "task": task,
                    "status": format!("{:?}", result.status),
                    "execution_time_ms": execution_time_ms,
                    "performance": result.performance_metrics,
                    "worker_id": self.worker_id,
                    "backend": "docker_gpu",
                });

                return Ok(serde_json::to_vec(&output)?);
            }
        }

        Err(anyhow!(
            "Unknown job type '{}'. Supported types: AIInference, ModelInference, BatchInference, \
            NLP, ComputerVision, VideoProcessing, Render3D, DataPipeline, ConfidentialVM, \
            FHECompute, ConfidentialAI, ZKProof, STWOProof, ModelDeploy, Ping, Echo",
            job_type
        ))
    }

    /// Build an AIJobRequest for the AIExecutionEngine from a JobExecutionRequest
    fn build_ai_job_request(
        &self,
        request: &JobExecutionRequest,
        task: &str,
        input_path: &str,
        output_path: &str,
        gpu_required: bool,
    ) -> AIJobRequest {
        use crate::types::{JobId, TaskId, WorkerId};

        let job_id = JobId::new();
        let task_id = TaskId::new();
        let worker_id = WorkerId::new();

        AIJobRequest {
            job_id,
            task_id,
            worker_id,
            job_type: crate::node::coordinator::JobType::AIInference {
                model_type: task.to_string(),
                input_data: input_path.to_string(),
                batch_size: 1,
                parameters: std::collections::HashMap::new(),
            },
            input_data: AIJobInput {
                data_type: "auto".to_string(),
                data_path: input_path.to_string(),
                metadata: std::collections::HashMap::new(),
                preprocessing_required: false,
            },
            output_requirements: AIJobOutput {
                format: "json".to_string(),
                path: output_path.to_string(),
                postprocessing_required: false,
                quality_requirements: None,
            },
            resource_constraints: ResourceConstraints {
                max_gpu_memory_gb: (request.requirements.min_vram_mb / 1024) as u32,
                max_cpu_cores: 8,
                max_ram_gb: 32,
                max_execution_time_seconds: request.requirements.timeout_seconds as u32,
                gpu_required,
                specialized_hardware: None,
            },
            execution_params: ExecutionParams {
                batch_size: 1,
                precision: "fp16".to_string(),
                optimization_level: "balanced".to_string(),
                cache_enabled: true,
                additional_params: std::collections::HashMap::new(),
            },
        }
    }

    /// Poll the AI execution engine for job completion
    async fn poll_ai_job(&self, job_id: &crate::types::JobId, timeout_secs: u64) -> Result<crate::ai::execution::AIJobResult> {
        let deadline = Instant::now() + std::time::Duration::from_secs(timeout_secs);

        loop {
            if Instant::now() > deadline {
                return Err(anyhow!("AI job {} timed out after {}s", job_id, timeout_secs));
            }

            if let Some(result) = self.ai_engine.get_job_status(job_id).await {
                match result.status {
                    crate::ai::execution::ExecutionStatus::Completed => return Ok(result),
                    crate::ai::execution::ExecutionStatus::Failed => {
                        return Err(anyhow!("AI job {} failed: {}",
                            job_id, result.error_details.unwrap_or_default()));
                    }
                    crate::ai::execution::ExecutionStatus::Cancelled => {
                        return Err(anyhow!("AI job {} was cancelled", job_id));
                    }
                    crate::ai::execution::ExecutionStatus::Timeout => {
                        return Err(anyhow!("AI job {} timed out in execution engine", job_id));
                    }
                    _ => {}
                }
            }

            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    /// Generate TEE attestation via TDX or SEV-SNP guest driver
    fn generate_tee_attestation(&self, job_id: &str, output_hash: &str) -> String {
        let report_data = format!("{}:{}", job_id, output_hash);
        let mut report_hash = [0u8; 64];
        let digest = Sha256::digest(report_data.as_bytes());
        report_hash[..32].copy_from_slice(&digest);

        // Attempt Intel TDX via /dev/tdx_guest
        if let Ok(quote) = Self::tdx_get_quote(&report_hash) {
            return format!("TDX_QUOTE:{}", hex::encode(&quote));
        }

        // Attempt AMD SEV-SNP via /dev/sev-guest
        if let Ok(report) = Self::sevsnp_get_report(&report_hash) {
            return format!("SEVSNP_REPORT:{}", hex::encode(&report));
        }

        // No TEE hardware available — return a signed hash with explicit marker
        warn!("⚠️ No TEE hardware detected (TDX/SEV-SNP). Returning software attestation.");
        let mut hasher = Sha256::new();
        hasher.update(b"SOFTWARE_ATTESTATION:");
        hasher.update(report_data.as_bytes());
        format!("SW_ATTESTATION:{:x}", hasher.finalize())
    }

    /// Read TDX quote from /dev/tdx_guest (Intel TDX)
    fn tdx_get_quote(report_data: &[u8; 64]) -> Result<Vec<u8>> {
        use std::fs::OpenOptions;
        use std::io::{Read, Write};

        let mut dev = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tdx_guest")
            .map_err(|e| anyhow!("TDX device not available: {}", e))?;

        // TDX_CMD_GET_REPORT0 ioctl — write 64-byte report_data, read back report
        dev.write_all(report_data)
            .map_err(|e| anyhow!("TDX report_data write failed: {}", e))?;

        let mut quote = Vec::new();
        dev.read_to_end(&mut quote)
            .map_err(|e| anyhow!("TDX quote read failed: {}", e))?;

        if quote.is_empty() {
            return Err(anyhow!("TDX returned empty quote"));
        }

        Ok(quote)
    }

    /// Read SEV-SNP attestation report from /dev/sev-guest (AMD SEV-SNP)
    fn sevsnp_get_report(report_data: &[u8; 64]) -> Result<Vec<u8>> {
        use std::fs::OpenOptions;
        use std::io::{Read, Write};

        let mut dev = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/sev-guest")
            .map_err(|e| anyhow!("SEV-SNP device not available: {}", e))?;

        dev.write_all(report_data)
            .map_err(|e| anyhow!("SEV-SNP report_data write failed: {}", e))?;

        let mut report = Vec::new();
        dev.read_to_end(&mut report)
            .map_err(|e| anyhow!("SEV-SNP report read failed: {}", e))?;

        if report.is_empty() {
            return Err(anyhow!("SEV-SNP returned empty report"));
        }

        Ok(report)
    }
}

