//! # Job Executor
//!
//! Executes different types of compute jobs (AI, Data, VM, FHE, etc.)
//! Now includes ZK proof generation via ObelyskExecutor and FHE support

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use tracing::{info, warn, debug};
use std::time::Instant;
use sha2::{Sha256, Digest};
use hex;

use crate::compute::obelysk_executor::{ObelyskExecutor, ObelyskExecutorConfig, ObelyskJobStatus};
use crate::obelysk::proof_compression::CompressedProof;
use crate::obelysk::compute_invoice::{ComputeInvoice, InvoiceBuilder};

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
}

impl JobExecutor {
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

    /// Execute AI Inference job (e.g., Stable Diffusion, LLM)
    async fn execute_ai_inference(&self, request: &JobExecutionRequest) -> Result<Vec<u8>> {
        info!("🤖 Running AI Inference...");
        
        // Simulate AI model inference
        // In production, this would:
        // 1. Load model from cache or download
        // 2. Preprocess input
        // 3. Run inference (PyTorch, ONNX, etc.)
        // 4. Postprocess output
        
        let _payload_str = String::from_utf8_lossy(&request.payload);
        debug!("Input payload size: {} bytes", request.payload.len());
        
        // Simulate processing time based on input size
        let processing_time = std::cmp::max(100, request.payload.len() / 100);
        tokio::time::sleep(tokio::time::Duration::from_millis(processing_time as u64)).await;
        
        // Mock result: In reality, this would be model output
        let result = serde_json::json!({
            "model": "stable-diffusion-v2",
            "input_hash": format!("{:x}", Sha256::digest(&request.payload)),
            "output_type": "image/png",
            "dimensions": [512, 512],
            "processing_time_ms": processing_time,
            "worker_id": self.worker_id,
            "tee_enabled": self.has_tee,
        });
        
        Ok(serde_json::to_vec(&result)?)
    }

    /// Execute Data Pipeline job (SQL, ETL)
    async fn execute_data_pipeline(&self, request: &JobExecutionRequest) -> Result<Vec<u8>> {
        info!("📊 Running Data Pipeline...");
        
        // In production, this would use DataFusion:
        // 1. Parse SQL query
        // 2. Connect to data sources (S3, Parquet, CSV)
        // 3. Execute query with DataFusion
        // 4. Return result set
        
        let payload_str = String::from_utf8_lossy(&request.payload);
        debug!("SQL/Pipeline input: {}", payload_str);
        
        // Simulate data processing
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
        
        let result = serde_json::json!({
            "engine": "datafusion",
            "rows_processed": 1000,
            "execution_plan": "ProjectionExec -> FilterExec -> ScanExec",
            "output_rows": 42,
            "output_schema": ["id", "name", "value"],
            "confidential": self.has_tee,
        });
        
        Ok(serde_json::to_vec(&result)?)
    }

    /// Execute Confidential VM job
    async fn execute_confidential_vm(&self, request: &JobExecutionRequest) -> Result<Vec<u8>> {
        info!("🔒 Running Confidential VM...");
        
        if !self.has_tee {
            return Err(anyhow!("TEE required but not available"));
        }
        
        // In production:
        // 1. Spin up confidential container
        // 2. Execute payload in isolated environment
        // 3. Generate TEE attestation
        // 4. Destroy container
        
        tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
        
        let result = serde_json::json!({
            "vm_type": "confidential_container",
            "tee_platform": "Intel TDX",
            "measurement": format!("{:x}", Sha256::digest(&request.payload)),
            "exit_code": 0,
        });
        
        Ok(serde_json::to_vec(&result)?)
    }

    /// Execute 3D Rendering job
    async fn execute_3d_render(&self, request: &JobExecutionRequest) -> Result<Vec<u8>> {
        info!("🎨 Rendering 3D scene...");
        
        // Simulate GPU rendering
        let frames = request.payload.len() / 1000 + 1;
        let render_time = frames * 100; // 100ms per frame
        
        tokio::time::sleep(tokio::time::Duration::from_millis(render_time as u64)).await;
        
        let result = serde_json::json!({
            "renderer": "cycles",
            "frames_rendered": frames,
            "resolution": [1920, 1080],
            "samples": 128,
        });
        
        Ok(serde_json::to_vec(&result)?)
    }

    /// Execute Video Processing job
    async fn execute_video_processing(&self, request: &JobExecutionRequest) -> Result<Vec<u8>> {
        info!("🎬 Processing video...");
        
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        
        let result = serde_json::json!({
            "codec": "h264",
            "input_size_mb": request.payload.len() / 1024 / 1024,
            "output_size_mb": request.payload.len() / 1024 / 1024 / 2,
            "fps": 30,
            "duration_seconds": 10,
        });
        
        Ok(serde_json::to_vec(&result)?)
    }

    /// Execute Computer Vision job
    async fn execute_computer_vision(&self, _request: &JobExecutionRequest) -> Result<Vec<u8>> {
        info!("👁️  Running Computer Vision...");
        
        tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;
        
        let result = serde_json::json!({
            "model": "yolov8",
            "detections": 5,
            "classes": ["person", "car", "dog"],
            "confidence_threshold": 0.8,
        });
        
        Ok(serde_json::to_vec(&result)?)
    }

    /// Execute NLP job
    async fn execute_nlp(&self, request: &JobExecutionRequest) -> Result<Vec<u8>> {
        info!("📝 Running NLP task...");

        let text = String::from_utf8_lossy(&request.payload);
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let result = serde_json::json!({
            "model": "bert-base",
            "input_tokens": text.split_whitespace().count(),
            "task": "sentiment_analysis",
            "result": "positive",
            "confidence": 0.95,
        });

        Ok(serde_json::to_vec(&result)?)
    }

    /// Execute FHE (Fully Homomorphic Encryption) compute job
    /// Performs computations on encrypted data without decryption
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
                operation: fhe_request.operation,
                worker_id: self.worker_id.clone(),
                tee_protected: self.has_tee,
            };

            info!("✅ FHE compute completed in {}ms", compute_time_ms);
            Ok(serde_json::to_vec(&response)?)
        }

        #[cfg(not(feature = "fhe"))]
        {
            let _ = request;
            Err(anyhow!("FHE feature not enabled. Build with --features fhe"))
        }
    }

    /// Execute Confidential AI job - AI inference on FHE-encrypted data
    /// Combines FHE encryption with AI model execution for fully private inference
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

            info!("📊 Processing {} encrypted features through {} layers",
                encrypted_inputs.len(), conf_request.model_weights.len());

            // Perform encrypted neural network inference
            // Each layer: output = activation(weights . input)
            let mut current_layer = encrypted_inputs;

            for (layer_idx, layer_weights) in conf_request.model_weights.iter().enumerate() {
                info!("  Layer {}: {} neurons", layer_idx + 1, layer_weights.len());

                // For each neuron in this layer, compute weighted sum
                let mut layer_output = Vec::new();

                for neuron_weights in layer_weights {
                    // Deserialize neuron weights
                    let mut weights = Vec::new();
                    for w in neuron_weights {
                        let weight = EncryptedValue::deserialize(w)
                            .map_err(|e| anyhow!("Failed to deserialize weight: {:?}", e))?;
                        weights.push(weight);
                    }

                    // Compute dot product (weights . inputs)
                    if weights.len() == current_layer.len() {
                        let dot = FheCompute::dot_product(&weights, &current_layer, &server_key)
                            .map_err(|e| anyhow!("Dot product failed: {:?}", e))?;

                        // Apply ReLU activation (for unsigned, this is identity)
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
                model_type: conf_request.model_type,
                layers_processed: conf_request.model_weights.len(),
                worker_id: self.worker_id.clone(),
                tee_protected: self.has_tee,
            };

            info!("✅ Confidential AI inference completed in {}ms", compute_time_ms);
            Ok(serde_json::to_vec(&response)?)
        }

        #[cfg(not(feature = "fhe"))]
        {
            let _ = request;
            Err(anyhow!("FHE feature not enabled. Build with --features fhe"))
        }
    }

    /// Execute explicit ZK Proof generation job (STWO)
    /// This is for when users explicitly want a ZK proof of their computation
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

                let response = ZkProofResponse {
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
                };

                info!("✅ ZK Proof generated: {} bytes, {}ms", response.proof_size_bytes, proof_time_ms);
                Ok(serde_json::to_vec(&response)?)
            }
            Err(e) => {
                Err(anyhow!("ZK proof generation failed: {}", e))
            }
        }
    }

    /// Execute model deployment job
    /// Downloads/caches model and returns deployment endpoint
    async fn execute_model_deploy(&self, request: &JobExecutionRequest) -> Result<Vec<u8>> {
        info!("🚀 Deploying model...");
        let start = Instant::now();

        // Parse deployment request
        let deploy_request: ModelDeployRequest = serde_json::from_slice(&request.payload)
            .map_err(|e| anyhow!("Invalid model deploy request: {}", e))?;

        // Simulate model download/setup
        // In production: download from HuggingFace, S3, or IPFS
        let setup_time = match deploy_request.model_size.as_str() {
            "small" => 500,
            "medium" => 1500,
            "large" => 3000,
            "xlarge" => 5000,
            _ => 1000,
        };

        tokio::time::sleep(tokio::time::Duration::from_millis(setup_time)).await;

        let deployment_time_ms = start.elapsed().as_millis() as u64;
        let model_id = format!("model-{}", uuid::Uuid::new_v4().to_string()[..8].to_string());

        let response = ModelDeployResponse {
            model_id: model_id.clone(),
            model_name: deploy_request.model_name.clone(),
            endpoint: format!("/api/models/{}/inference", model_id),
            status: "deployed".to_string(),
            worker_id: self.worker_id.clone(),
            deployment_time_ms,
            estimated_inference_time_ms: match deploy_request.model_size.as_str() {
                "small" => 50,
                "medium" => 150,
                "large" => 300,
                "xlarge" => 500,
                _ => 100,
            },
            vram_used_mb: match deploy_request.model_size.as_str() {
                "small" => 2048,
                "medium" => 8192,
                "large" => 24576,
                "xlarge" => 49152,
                _ => 4096,
            },
            supported_batch_sizes: vec![1, 2, 4, 8, 16, 32],
        };

        info!("✅ Model {} deployed in {}ms", deploy_request.model_name, deployment_time_ms);
        Ok(serde_json::to_vec(&response)?)
    }

    /// Execute model inference job
    async fn execute_model_inference(&self, request: &JobExecutionRequest) -> Result<Vec<u8>> {
        info!("🧠 Running model inference...");
        let start = Instant::now();

        // Parse inference request
        let inference_request: ModelInferenceRequest = serde_json::from_slice(&request.payload)
            .map_err(|e| anyhow!("Invalid inference request: {}", e))?;

        // Simulate inference based on model type
        let inference_time = match inference_request.model_type.as_str() {
            "llm" => 500 + (inference_request.max_tokens.unwrap_or(100) * 10) as u64,
            "image_gen" => 2000,
            "embedding" => 50,
            "classification" => 100,
            "object_detection" => 150,
            _ => 200,
        };

        tokio::time::sleep(tokio::time::Duration::from_millis(inference_time)).await;

        let inference_time_ms = start.elapsed().as_millis() as u64;

        // Generate mock output based on model type
        let output = match inference_request.model_type.as_str() {
            "llm" => serde_json::json!({
                "text": "This is a generated response from the LLM model deployed on BitSage GPU network.",
                "tokens_generated": inference_request.max_tokens.unwrap_or(50),
                "finish_reason": "stop"
            }),
            "image_gen" => serde_json::json!({
                "image_url": "ipfs://QmExample...",
                "dimensions": [512, 512],
                "steps": 50
            }),
            "embedding" => serde_json::json!({
                "embedding": vec![0.1f32; 768],
                "dimensions": 768
            }),
            "classification" => serde_json::json!({
                "label": "positive",
                "confidence": 0.95,
                "all_scores": {"positive": 0.95, "negative": 0.05}
            }),
            _ => serde_json::json!({
                "result": "inference completed",
                "output_type": inference_request.model_type
            }),
        };

        let response = ModelInferenceResponse {
            model_id: inference_request.model_id.clone(),
            output,
            inference_time_ms,
            tokens_processed: inference_request.max_tokens.unwrap_or(100) as u64,
            worker_id: self.worker_id.clone(),
            gpu_memory_used_mb: 4096,
        };

        info!("✅ Inference completed in {}ms", inference_time_ms);
        Ok(serde_json::to_vec(&response)?)
    }

    /// Execute batch inference job for multiple inputs
    async fn execute_batch_inference(&self, request: &JobExecutionRequest) -> Result<Vec<u8>> {
        info!("📦 Running batch inference...");
        let start = Instant::now();

        // Parse batch request
        let batch_request: BatchInferenceRequest = serde_json::from_slice(&request.payload)
            .map_err(|e| anyhow!("Invalid batch inference request: {}", e))?;

        let batch_size = batch_request.inputs.len();
        info!("  Processing batch of {} inputs", batch_size);

        // Simulate batch processing (faster per-item than individual)
        let per_item_time = 50; // ms per item in batch
        let total_time = (batch_size as u64 * per_item_time).max(100);

        tokio::time::sleep(tokio::time::Duration::from_millis(total_time)).await;

        let batch_time_ms = start.elapsed().as_millis() as u64;

        // Generate outputs for each input
        let outputs: Vec<serde_json::Value> = batch_request.inputs.iter()
            .enumerate()
            .map(|(i, _)| serde_json::json!({
                "index": i,
                "result": format!("batch_output_{}", i),
                "confidence": 0.9 + (i as f64 * 0.01).min(0.09)
            }))
            .collect();

        let response = BatchInferenceResponse {
            model_id: batch_request.model_id,
            outputs,
            batch_size,
            total_time_ms: batch_time_ms,
            avg_time_per_item_ms: batch_time_ms / batch_size as u64,
            worker_id: self.worker_id.clone(),
            gpu_utilization: 0.85,
        };

        info!("✅ Batch inference completed: {} items in {}ms ({} ms/item avg)",
              batch_size, batch_time_ms, batch_time_ms / batch_size as u64);
        Ok(serde_json::to_vec(&response)?)
    }

    // ========================================================================
    // Simple Pipeline Test Jobs (Ping/Echo)
    // ========================================================================

    /// Execute Ping job - simple pipeline verification
    /// Proves: Coordinator → Worker → Execution → Response
    async fn execute_ping(&self, _request: &JobExecutionRequest) -> Result<Vec<u8>> {
        info!("🏓 Executing Ping job...");

        let response = serde_json::json!({
            "response": "pong",
            "worker_id": self.worker_id,
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "proofs_enabled": self.enable_proofs,
            "tee_available": self.has_tee,
            "message": "BitSage pipeline verified - worker is operational!"
        });

        Ok(serde_json::to_vec(&response)?)
    }

    /// Execute Echo job - returns the payload back
    /// Proves: Data integrity through the pipeline
    async fn execute_echo(&self, request: &JobExecutionRequest) -> Result<Vec<u8>> {
        info!("📢 Executing Echo job...");

        // Parse payload as string if possible
        let payload_str = String::from_utf8_lossy(&request.payload);

        let response = serde_json::json!({
            "echo": payload_str,
            "original_size_bytes": request.payload.len(),
            "worker_id": self.worker_id,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });

        Ok(serde_json::to_vec(&response)?)
    }

    // ========================================================================
    // Generic/Fallback
    // ========================================================================

    /// Generic executor for unknown job types
    async fn execute_generic(&self, request: &JobExecutionRequest) -> Result<Vec<u8>> {
        info!("⚙️  Running generic job...");

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let result = serde_json::json!({
            "status": "completed",
            "input_hash": format!("{:x}", Sha256::digest(&request.payload)),
            "worker_id": self.worker_id,
        });

        Ok(serde_json::to_vec(&result)?)
    }

    /// Generate TEE attestation (mock for now)
    fn generate_tee_attestation(&self, job_id: &str, output_hash: &str) -> String {
        // In production, this would:
        // 1. Call TDX/SEV-SNP API
        // 2. Generate attestation report
        // 3. Sign with TEE private key
        
        let attestation_data = format!("{}:{}", job_id, output_hash);
        let mut hasher = Sha256::new();
        hasher.update(attestation_data.as_bytes());
        format!("TEE_QUOTE:{:x}", hasher.finalize())
    }
}

