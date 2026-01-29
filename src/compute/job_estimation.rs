//! Job Cost and Duration Estimation
//!
//! Estimates the cost and duration for different job types based on:
//! - Job complexity and type
//! - Resource requirements (GPU, memory, CPU)
//! - Historical execution data
//! - Current network pricing

use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use tracing::debug;

use crate::node::coordinator::JobType;

/// Job estimation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobEstimate {
    /// Estimated execution duration in seconds
    pub duration_secs: u64,
    /// Estimated cost in SAGE wei (smallest unit)
    pub cost_wei: u128,
    /// Estimated cost formatted for display
    pub cost_formatted: String,
    /// Number of tasks the job will be split into
    pub estimated_tasks: u32,
    /// Whether GPU acceleration is required
    pub requires_gpu: bool,
    /// Estimated memory requirement in MB
    pub memory_mb: u64,
    /// Confidence level (0.0 - 1.0)
    pub confidence: f32,
    /// Breakdown of cost components
    pub cost_breakdown: CostBreakdown,
}

/// Breakdown of cost components
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostBreakdown {
    /// Base platform fee
    pub platform_fee: u128,
    /// GPU compute cost
    pub gpu_cost: u128,
    /// Memory cost
    pub memory_cost: u128,
    /// Time-based cost
    pub time_cost: u128,
    /// Priority multiplier applied
    pub priority_multiplier: f32,
}

/// Pricing configuration
#[derive(Debug, Clone)]
pub struct PricingConfig {
    /// Base platform fee per job (in wei)
    pub base_platform_fee: u128,
    /// Cost per GPU-second (in wei)
    pub gpu_second_rate: u128,
    /// Cost per GB-second of memory (in wei)
    pub memory_gb_second_rate: u128,
    /// Cost per second of execution (in wei)
    pub time_second_rate: u128,
    /// Priority multipliers by priority level (1-10)
    pub priority_multipliers: HashMap<u8, f32>,
}

impl Default for PricingConfig {
    fn default() -> Self {
        let mut priority_multipliers = HashMap::new();
        priority_multipliers.insert(1, 0.5);  // Lowest priority - 50% off
        priority_multipliers.insert(2, 0.6);
        priority_multipliers.insert(3, 0.7);
        priority_multipliers.insert(4, 0.8);
        priority_multipliers.insert(5, 1.0);  // Normal priority
        priority_multipliers.insert(6, 1.2);
        priority_multipliers.insert(7, 1.4);
        priority_multipliers.insert(8, 1.6);
        priority_multipliers.insert(9, 1.8);
        priority_multipliers.insert(10, 2.0); // Highest priority - 2x cost

        Self {
            // Base fee: 0.001 SAGE
            base_platform_fee: 1_000_000_000_000_000,
            // GPU: 0.0001 SAGE per GPU-second
            gpu_second_rate: 100_000_000_000_000,
            // Memory: 0.00001 SAGE per GB-second
            memory_gb_second_rate: 10_000_000_000_000,
            // Time: 0.00005 SAGE per second
            time_second_rate: 50_000_000_000_000,
            priority_multipliers,
        }
    }
}

/// Job estimator service
#[derive(Debug, Clone)]
pub struct JobEstimator {
    config: PricingConfig,
}

impl JobEstimator {
    /// Create a new job estimator with default pricing
    pub fn new() -> Self {
        Self {
            config: PricingConfig::default(),
        }
    }

    /// Create with custom pricing config
    pub fn with_config(config: PricingConfig) -> Self {
        Self { config }
    }

    /// Estimate cost and duration for a job
    pub fn estimate(&self, job_type: &JobType, priority: u8) -> JobEstimate {
        let (base_duration, base_memory, requires_gpu, task_count, confidence) =
            self.estimate_base_metrics(job_type);

        let priority_mult = *self.config.priority_multipliers
            .get(&priority.clamp(1, 10))
            .unwrap_or(&1.0);

        // Calculate cost breakdown
        let gpu_cost = if requires_gpu {
            self.config.gpu_second_rate * base_duration as u128
        } else {
            0
        };

        let memory_gb = (base_memory as f64 / 1024.0).max(1.0);
        let memory_cost = (self.config.memory_gb_second_rate as f64
            * memory_gb
            * base_duration as f64) as u128;

        let time_cost = self.config.time_second_rate * base_duration as u128;

        // Total cost with priority multiplier
        let subtotal = self.config.base_platform_fee + gpu_cost + memory_cost + time_cost;
        let total_cost = (subtotal as f64 * priority_mult as f64) as u128;

        let cost_breakdown = CostBreakdown {
            platform_fee: self.config.base_platform_fee,
            gpu_cost,
            memory_cost,
            time_cost,
            priority_multiplier: priority_mult,
        };

        debug!(
            "Job estimate: type={}, duration={}s, cost={} wei, tasks={}, gpu={}",
            job_type, base_duration, total_cost, task_count, requires_gpu
        );

        JobEstimate {
            duration_secs: base_duration,
            cost_wei: total_cost,
            cost_formatted: format_sage_amount(total_cost),
            estimated_tasks: task_count,
            requires_gpu,
            memory_mb: base_memory,
            confidence,
            cost_breakdown,
        }
    }

    /// Estimate base metrics based on job type
    fn estimate_base_metrics(&self, job_type: &JobType) -> (u64, u64, bool, u32, f32) {
        // Returns: (duration_secs, memory_mb, requires_gpu, task_count, confidence)
        match job_type {
            JobType::AIInference { model_type, batch_size, .. } => {
                let complexity = self.estimate_model_complexity(model_type);
                let duration = 30 + (complexity * *batch_size as u64 / 10);
                let memory = 2048 + (complexity * 256);
                let tasks = (*batch_size / 10).max(1);
                (duration, memory, true, tasks, 0.8)
            }

            JobType::ComputerVision { task_type, input_images, batch_size, .. } => {
                let per_image_time = match task_type {
                    crate::node::coordinator::CVTaskType::ImageGeneration => 30,
                    crate::node::coordinator::CVTaskType::StyleTransfer => 15,
                    crate::node::coordinator::CVTaskType::ObjectDetection => 2,
                    crate::node::coordinator::CVTaskType::ImageSegmentation => 5,
                    crate::node::coordinator::CVTaskType::SuperResolution => 10,
                    _ => 3,
                };
                let image_count = input_images.len().max(*batch_size as usize);
                let duration = (per_image_time * image_count as u64).max(10);
                let memory = 4096 + (image_count as u64 * 50);
                let tasks = (image_count as u32 / 10).max(1);
                (duration, memory, true, tasks, 0.75)
            }

            JobType::NLP { task_type, input_text, max_tokens, .. } => {
                let per_text_time = match task_type {
                    crate::node::coordinator::NLPTaskType::TextGeneration => 5,
                    crate::node::coordinator::NLPTaskType::TextSummarization => 3,
                    crate::node::coordinator::NLPTaskType::Translation => 2,
                    crate::node::coordinator::NLPTaskType::SentimentAnalysis => 1,
                    crate::node::coordinator::NLPTaskType::CodeGeneration => 10,
                    _ => 2,
                };
                let text_count = input_text.len().max(1);
                let token_factor = (*max_tokens as f64 / 1000.0).max(1.0);
                let duration = ((per_text_time * text_count as u64) as f64 * token_factor) as u64;
                let memory = 4096 + (*max_tokens as u64 * 2);
                let tasks = (text_count as u32 / 10).max(1);
                (duration.max(10), memory, true, tasks, 0.7)
            }

            JobType::VideoProcessing { duration: video_duration, frame_rate, resolution, .. } => {
                let total_frames = (*video_duration * *frame_rate) as u64;
                let pixels = (resolution.0 as u64) * (resolution.1 as u64);
                let complexity_factor = (pixels as f64 / (1920.0 * 1080.0)).max(1.0);
                let duration = ((total_frames as f64 * 0.1 * complexity_factor) as u64).max(30);
                let memory = 4096 + (pixels / 1000);
                let tasks = ((total_frames / 25) as u32).max(1).min(100);
                (duration, memory, true, tasks, 0.85)
            }

            JobType::Render3D { output_resolution, frames, quality_preset, .. } => {
                let frame_count = frames.unwrap_or(1) as u64;
                let pixels = (output_resolution.0 as u64) * (output_resolution.1 as u64);
                let quality_mult = match quality_preset.to_lowercase().as_str() {
                    "low" => 0.5,
                    "medium" => 1.0,
                    "high" => 2.0,
                    "ultra" => 4.0,
                    _ => 1.0,
                };
                let per_frame_time = ((pixels as f64 / 2073600.0) * 60.0 * quality_mult) as u64;
                let duration = (per_frame_time * frame_count).max(60);
                let memory = 8192 + (pixels / 500);
                let tasks = (frame_count as u32).max(1).min(100);
                (duration, memory, true, tasks, 0.75)
            }

            JobType::AudioProcessing { task_type, input_audio, .. } => {
                let per_file_time = match task_type {
                    crate::node::coordinator::AudioTaskType::SpeechToText => 10,
                    crate::node::coordinator::AudioTaskType::TextToSpeech => 5,
                    crate::node::coordinator::AudioTaskType::MusicGeneration => 60,
                    crate::node::coordinator::AudioTaskType::VoiceConversion => 20,
                    _ => 5,
                };
                let file_count = input_audio.len().max(1);
                let duration = (per_file_time * file_count as u64).max(10);
                let memory = 2048 + (file_count as u64 * 100);
                let tasks = (file_count as u32 / 5).max(1);
                (duration, memory, true, tasks, 0.7)
            }

            JobType::TimeSeriesAnalysis { input_data, task_type, forecast_horizon, .. } => {
                let data_points = input_data.len() as u64;
                let base_time = match task_type {
                    crate::node::coordinator::TimeSeriesTaskType::Forecasting => 5,
                    crate::node::coordinator::TimeSeriesTaskType::AnomalyDetection => 3,
                    _ => 2,
                };
                let horizon_factor = (*forecast_horizon as f64 / 100.0).max(1.0);
                let duration = ((data_points / 100 * base_time) as f64 * horizon_factor) as u64;
                let memory = 1024 + (data_points / 10);
                (duration.max(10), memory, false, 1, 0.8)
            }

            JobType::MultimodalAI { task_type, .. } => {
                let duration = match task_type {
                    crate::node::coordinator::MultimodalTaskType::VideoUnderstanding => 120,
                    crate::node::coordinator::MultimodalTaskType::ImageCaptioning => 10,
                    crate::node::coordinator::MultimodalTaskType::VisualQuestionAnswering => 15,
                    _ => 30,
                };
                (duration, 8192, true, 1, 0.65)
            }

            JobType::ReinforcementLearning { training_steps, .. } => {
                let duration = (*training_steps / 100).max(60);
                let memory = 8192;
                (duration, memory, true, 1, 0.5)
            }

            JobType::SpecializedAI { computational_requirements, .. } => {
                let duration = (computational_requirements.estimated_runtime_minutes * 60) as u64;
                let memory = (computational_requirements.min_ram_gb * 1024) as u64;
                let requires_gpu = computational_requirements.min_gpu_memory_gb > 0;
                (duration.max(30), memory.max(2048), requires_gpu, 1, 0.6)
            }

            JobType::ZKProof { circuit_type, proof_system, .. } => {
                let base_time = match proof_system.to_lowercase().as_str() {
                    "stwo" => 120,
                    "stark" => 180,
                    "snark" | "groth16" => 90,
                    "plonk" => 100,
                    _ => 150,
                };
                let circuit_mult = if circuit_type.contains("large") { 3.0 }
                    else if circuit_type.contains("medium") { 2.0 }
                    else { 1.0 };
                let duration = (base_time as f64 * circuit_mult) as u64;
                (duration, 16384, true, 1, 0.7)
            }

            JobType::DataPipeline { tee_required, .. } => {
                let base_duration = if *tee_required { 120 } else { 60 };
                (base_duration, 4096, false, 1, 0.8)
            }

            JobType::ConfidentialVM { memory_mb, vcpu_count, .. } => {
                let duration = 300; // 5 min base for VM setup + execution
                let memory = *memory_mb as u64;
                let tasks = *vcpu_count;
                (duration, memory, false, tasks, 0.7)
            }

            JobType::Custom { parallelizable, .. } => {
                let duration = 120;
                let tasks = if *parallelizable { 4 } else { 1 };
                (duration, 2048, false, tasks, 0.5)
            }

            JobType::ModelTraining { num_gpus, .. } => {
                (3600, 65536, true, *num_gpus, 0.4)
            }

            JobType::RLTraining { training_steps, .. } => {
                let duration = (*training_steps / 50).max(120);
                (duration, 32768, true, 1, 0.4)
            }

            JobType::FHECompute { .. } => (300, 16384, true, 1, 0.6),
            JobType::ConfidentialAI { .. } => (600, 32768, true, 1, 0.5),
            JobType::ModelDeploy { .. } => (120, 16384, true, 1, 0.7),
            JobType::ModelInference { .. } => (10, 8192, true, 1, 0.8),
            JobType::BatchInference { batch_size, .. } => {
                let duration = (*batch_size as u64 * 5).max(10);
                let tasks = (*batch_size as u32 / 10).max(1);
                (duration, 16384, true, tasks, 0.75)
            }
        }
    }

    /// Estimate model complexity based on model name/type
    fn estimate_model_complexity(&self, model_type: &str) -> u64 {
        let model_lower = model_type.to_lowercase();

        if model_lower.contains("llama-70b") || model_lower.contains("gpt-4") {
            100
        } else if model_lower.contains("llama-13b") || model_lower.contains("gpt-3.5") {
            50
        } else if model_lower.contains("llama-7b") || model_lower.contains("mistral") {
            30
        } else if model_lower.contains("bert") || model_lower.contains("roberta") {
            10
        } else if model_lower.contains("resnet") || model_lower.contains("vgg") {
            5
        } else if model_lower.contains("yolo") || model_lower.contains("efficientnet") {
            8
        } else if model_lower.contains("stable-diffusion") || model_lower.contains("dall-e") {
            80
        } else if model_lower.contains("whisper") {
            15
        } else {
            20 // Default complexity
        }
    }

    /// Update estimate based on historical execution data
    pub fn refine_estimate(&self, estimate: &mut JobEstimate, historical_avg_duration: Option<u64>, historical_avg_cost: Option<u128>) {
        if let Some(hist_duration) = historical_avg_duration {
            // Blend estimated and historical duration (70% historical, 30% estimated)
            let blended_duration = (hist_duration as f64 * 0.7 + estimate.duration_secs as f64 * 0.3) as u64;
            estimate.duration_secs = blended_duration;
            estimate.confidence = (estimate.confidence + 0.1).min(0.95);
        }

        if let Some(hist_cost) = historical_avg_cost {
            let blended_cost = (hist_cost as f64 * 0.7 + estimate.cost_wei as f64 * 0.3) as u128;
            estimate.cost_wei = blended_cost;
            estimate.cost_formatted = format_sage_amount(blended_cost);
        }
    }
}

impl Default for JobEstimator {
    fn default() -> Self {
        Self::new()
    }
}

/// Format SAGE amount from wei to human-readable string
fn format_sage_amount(wei: u128) -> String {
    let sage = wei as f64 / 1e18;
    if sage >= 1000.0 {
        format!("{:.2}K SAGE", sage / 1000.0)
    } else if sage >= 1.0 {
        format!("{:.4} SAGE", sage)
    } else if sage >= 0.001 {
        format!("{:.6} SAGE", sage)
    } else if wei > 0 {
        format!("{} wei", wei)
    } else {
        "0 SAGE".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_ai_inference_estimate() {
        let estimator = JobEstimator::new();
        let job_type = JobType::AIInference {
            model_type: "llama-7b".to_string(),
            input_data: "test".to_string(),
            batch_size: 10,
            parameters: HashMap::new(),
        };

        let estimate = estimator.estimate(&job_type, 5);

        assert!(estimate.duration_secs > 0);
        assert!(estimate.cost_wei > 0);
        assert!(estimate.requires_gpu);
        assert!(estimate.confidence > 0.0);
    }

    #[test]
    fn test_video_processing_estimate() {
        let estimator = JobEstimator::new();
        let job_type = JobType::VideoProcessing {
            input_file: "test.mp4".to_string(),
            output_format: "mp4".to_string(),
            resolution: (1920, 1080),
            frame_rate: 30.0,
            duration: 60.0,
        };

        let estimate = estimator.estimate(&job_type, 5);

        assert!(estimate.duration_secs >= 30);
        assert!(estimate.estimated_tasks >= 1);
        assert!(estimate.requires_gpu);
    }

    #[test]
    fn test_zk_proof_estimate() {
        let estimator = JobEstimator::new();
        let job_type = JobType::ZKProof {
            circuit_type: "stark_medium".to_string(),
            input_data: "test".to_string(),
            proof_system: "stwo".to_string(),
        };

        let estimate = estimator.estimate(&job_type, 5);

        assert!(estimate.duration_secs >= 120);
        assert!(estimate.memory_mb >= 16384);
        assert!(estimate.requires_gpu);
    }

    #[test]
    fn test_priority_affects_cost() {
        let estimator = JobEstimator::new();
        let job_type = JobType::AIInference {
            model_type: "bert".to_string(),
            input_data: "test".to_string(),
            batch_size: 1,
            parameters: HashMap::new(),
        };

        let low_priority = estimator.estimate(&job_type, 1);
        let high_priority = estimator.estimate(&job_type, 10);

        assert!(high_priority.cost_wei > low_priority.cost_wei);
        // High priority should be ~4x low priority (2.0/0.5)
        let ratio = high_priority.cost_wei as f64 / low_priority.cost_wei as f64;
        assert!((ratio - 4.0).abs() < 0.1);
    }

    #[test]
    fn test_format_sage_amount() {
        assert_eq!(format_sage_amount(0), "0 SAGE");
        assert_eq!(format_sage_amount(1_000_000_000_000_000), "0.001000 SAGE");
        assert_eq!(format_sage_amount(1_000_000_000_000_000_000), "1.0000 SAGE");
        assert!(format_sage_amount(1_000_000_000_000_000_000_000).contains("K SAGE"));
    }

    #[test]
    fn test_refine_estimate() {
        let estimator = JobEstimator::new();
        let job_type = JobType::AIInference {
            model_type: "bert".to_string(),
            input_data: "test".to_string(),
            batch_size: 1,
            parameters: HashMap::new(),
        };

        let mut estimate = estimator.estimate(&job_type, 5);
        let original_duration = estimate.duration_secs;
        let original_confidence = estimate.confidence;

        estimator.refine_estimate(&mut estimate, Some(100), None);

        // Duration should be blended towards historical value
        assert_ne!(estimate.duration_secs, original_duration);
        // Confidence should increase
        assert!(estimate.confidence > original_confidence);
    }
}
