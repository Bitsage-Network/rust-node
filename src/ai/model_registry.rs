//! AI Model Registry
//!
//! This module provides a comprehensive registry for managing AI models across different
//! frameworks, domains, and task types. It handles model discovery, capability matching,
//! and resource requirements.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// Supported AI frameworks
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Framework {
    PyTorch,
    TensorFlow,
    ONNX,
    HuggingFace,
    OpenAI,
    Anthropic,
    Ollama,
    Whisper,
    StableDiffusion,
    Custom(String),
}

/// AI model categories
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AICategory {
    ComputerVision,
    NLP,
    Audio,
    TimeSeries,
    Multimodal,
    ReinforcementLearning,
    Specialized,
}

/// Hardware specifications required for model execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareSpec {
    pub min_gpu_memory_gb: u32,
    pub min_cpu_cores: u32,
    pub min_ram_gb: u32,
    pub preferred_gpu_types: Vec<String>,
    pub supports_cpu_only: bool,
    pub requires_specialized_hardware: bool,
    pub estimated_inference_time_ms: u32,
    pub max_batch_size: u32,
}

/// Model information and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    pub name: String,
    pub version: String,
    pub category: AICategory,
    pub framework: Framework,
    pub size_mb: u64,
    pub hardware_spec: HardwareSpec,
    pub supported_tasks: Vec<String>,
    pub input_formats: Vec<String>,
    pub output_formats: Vec<String>,
    pub model_url: Option<String>,
    pub license: String,
    pub description: String,
    pub performance_metrics: Option<PerformanceMetrics>,
}

/// Performance metrics for model evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub accuracy: Option<f32>,
    pub throughput_items_per_second: Option<f32>,
    pub latency_ms: Option<f32>,
    pub memory_usage_mb: Option<u32>,
    pub benchmark_dataset: Option<String>,
}

/// Model registry for managing AI models
pub struct ModelRegistry {
    models: HashMap<String, ModelInfo>,
    category_index: HashMap<AICategory, Vec<String>>,
    framework_index: HashMap<Framework, Vec<String>>,
    task_index: HashMap<String, Vec<String>>,
}

impl ModelRegistry {
    /// Create a new model registry with default models
    pub fn new() -> Self {
        let mut registry = Self {
            models: HashMap::new(),
            category_index: HashMap::new(),
            framework_index: HashMap::new(),
            task_index: HashMap::new(),
        };

        // Register default models
        registry.register_default_models();
        registry
    }

    /// Register a new model in the registry
    pub fn register_model(&mut self, model: ModelInfo) {
        let model_name = model.name.clone();

        // Update category index
        self.category_index
            .entry(model.category.clone())
            .or_insert_with(Vec::new)
            .push(model_name.clone());

        // Update framework index
        self.framework_index
            .entry(model.framework.clone())
            .or_insert_with(Vec::new)
            .push(model_name.clone());

        // Update task index
        for task in &model.supported_tasks {
            self.task_index
                .entry(task.clone())
                .or_insert_with(Vec::new)
                .push(model_name.clone());
        }

        // Store the model
        self.models.insert(model_name, model);
    }

    /// Get model information by name
    pub fn get_model(&self, name: &str) -> Option<&ModelInfo> {
        self.models.get(name)
    }

    /// Find models by category
    pub fn find_models_by_category(&self, category: &AICategory) -> Vec<&ModelInfo> {
        self.category_index
            .get(category)
            .map(|names| names.iter().filter_map(|name| self.models.get(name)).collect())
            .unwrap_or_default()
    }

    /// Find models by framework
    pub fn find_models_by_framework(&self, framework: &Framework) -> Vec<&ModelInfo> {
        self.framework_index
            .get(framework)
            .map(|names| names.iter().filter_map(|name| self.models.get(name)).collect())
            .unwrap_or_default()
    }

    /// Find models by task type
    pub fn find_models_by_task(&self, task: &str) -> Vec<&ModelInfo> {
        self.task_index
            .get(task)
            .map(|names| names.iter().filter_map(|name| self.models.get(name)).collect())
            .unwrap_or_default()
    }

    /// Find best model for a specific task and hardware constraints
    pub fn find_best_model(
        &self,
        task: &str,
        available_gpu_memory: u32,
        available_cpu_cores: u32,
        available_ram: u32,
    ) -> Option<&ModelInfo> {
        let candidates = self.find_models_by_task(task);
        
        candidates
            .into_iter()
            .filter(|model| {
                model.hardware_spec.min_gpu_memory_gb <= available_gpu_memory &&
                model.hardware_spec.min_cpu_cores <= available_cpu_cores &&
                model.hardware_spec.min_ram_gb <= available_ram
            })
            .min_by_key(|model| {
                // Prefer models with better performance metrics
                let latency_score = model.performance_metrics
                    .as_ref()
                    .and_then(|m| m.latency_ms)
                    .unwrap_or(1000.0) as u32;
                
                let memory_score = model.hardware_spec.min_gpu_memory_gb;
                
                // Combined score: lower is better
                latency_score + memory_score * 10
            })
    }

    /// Get all registered models
    pub fn get_all_models(&self) -> Vec<&ModelInfo> {
        self.models.values().collect()
    }

    /// Register default models for different AI categories
    fn register_default_models(&mut self) {
        // Computer Vision Models
        self.register_cv_models();
        
        // NLP Models
        self.register_nlp_models();
        
        // Audio Models
        self.register_audio_models();
        
        // Time Series Models
        self.register_time_series_models();
        
        // Multimodal Models
        self.register_multimodal_models();
        
        // Reinforcement Learning Models
        self.register_rl_models();
        
        // Specialized Domain Models
        self.register_specialized_models();
    }

    /// Register computer vision models
    fn register_cv_models(&mut self) {
        // YOLO v8 for object detection
        self.register_model(ModelInfo {
            name: "yolov8n".to_string(),
            version: "8.0".to_string(),
            category: AICategory::ComputerVision,
            framework: Framework::PyTorch,
            size_mb: 6,
            hardware_spec: HardwareSpec {
                min_gpu_memory_gb: 2,
                min_cpu_cores: 2,
                min_ram_gb: 4,
                preferred_gpu_types: vec!["GTX 1060".to_string(), "RTX 3060".to_string()],
                supports_cpu_only: true,
                requires_specialized_hardware: false,
                estimated_inference_time_ms: 50,
                max_batch_size: 16,
            },
            supported_tasks: vec!["object_detection".to_string()],
            input_formats: vec!["image/jpeg".to_string(), "image/png".to_string()],
            output_formats: vec!["application/json".to_string()],
            model_url: Some("https://github.com/ultralytics/ultralytics".to_string()),
            license: "AGPL-3.0".to_string(),
            description: "Real-time object detection model".to_string(),
            performance_metrics: Some(PerformanceMetrics {
                accuracy: Some(0.85),
                throughput_items_per_second: Some(20.0),
                latency_ms: Some(50.0),
                memory_usage_mb: Some(2048),
                benchmark_dataset: Some("COCO".to_string()),
            }),
        });

        // ResNet-50 for image classification
        self.register_model(ModelInfo {
            name: "resnet50".to_string(),
            version: "1.0".to_string(),
            category: AICategory::ComputerVision,
            framework: Framework::PyTorch,
            size_mb: 98,
            hardware_spec: HardwareSpec {
                min_gpu_memory_gb: 4,
                min_cpu_cores: 4,
                min_ram_gb: 8,
                preferred_gpu_types: vec!["RTX 3070".to_string(), "RTX 4070".to_string()],
                supports_cpu_only: true,
                requires_specialized_hardware: false,
                estimated_inference_time_ms: 100,
                max_batch_size: 32,
            },
            supported_tasks: vec!["image_classification".to_string()],
            input_formats: vec!["image/jpeg".to_string(), "image/png".to_string()],
            output_formats: vec!["application/json".to_string()],
            model_url: Some("https://pytorch.org/vision/stable/models.html".to_string()),
            license: "BSD-3-Clause".to_string(),
            description: "Deep residual network for image classification".to_string(),
            performance_metrics: Some(PerformanceMetrics {
                accuracy: Some(0.76),
                throughput_items_per_second: Some(10.0),
                latency_ms: Some(100.0),
                memory_usage_mb: Some(4096),
                benchmark_dataset: Some("ImageNet".to_string()),
            }),
        });

        // Stable Diffusion for image generation
        self.register_model(ModelInfo {
            name: "stable-diffusion-v1-5".to_string(),
            version: "1.5".to_string(),
            category: AICategory::ComputerVision,
            framework: Framework::StableDiffusion,
            size_mb: 4000,
            hardware_spec: HardwareSpec {
                min_gpu_memory_gb: 8,
                min_cpu_cores: 8,
                min_ram_gb: 16,
                preferred_gpu_types: vec!["RTX 3080".to_string(), "RTX 4080".to_string()],
                supports_cpu_only: false,
                requires_specialized_hardware: false,
                estimated_inference_time_ms: 5000,
                max_batch_size: 4,
            },
            supported_tasks: vec!["image_generation".to_string(), "style_transfer".to_string()],
            input_formats: vec!["text/plain".to_string()],
            output_formats: vec!["image/png".to_string()],
            model_url: Some("https://huggingface.co/runwayml/stable-diffusion-v1-5".to_string()),
            license: "CreativeML Open RAIL-M".to_string(),
            description: "Text-to-image generation model".to_string(),
            performance_metrics: Some(PerformanceMetrics {
                accuracy: None,
                throughput_items_per_second: Some(0.2),
                latency_ms: Some(5000.0),
                memory_usage_mb: Some(8192),
                benchmark_dataset: None,
            }),
        });
    }

    /// Register NLP models
    fn register_nlp_models(&mut self) {
        // BERT for text classification
        self.register_model(ModelInfo {
            name: "bert-base-uncased".to_string(),
            version: "1.0".to_string(),
            category: AICategory::NLP,
            framework: Framework::HuggingFace,
            size_mb: 440,
            hardware_spec: HardwareSpec {
                min_gpu_memory_gb: 4,
                min_cpu_cores: 4,
                min_ram_gb: 8,
                preferred_gpu_types: vec!["RTX 3060".to_string(), "RTX 4060".to_string()],
                supports_cpu_only: true,
                requires_specialized_hardware: false,
                estimated_inference_time_ms: 200,
                max_batch_size: 16,
            },
            supported_tasks: vec![
                "text_classification".to_string(),
                "sentiment_analysis".to_string(),
                "token_classification".to_string(),
            ],
            input_formats: vec!["text/plain".to_string()],
            output_formats: vec!["application/json".to_string()],
            model_url: Some("https://huggingface.co/bert-base-uncased".to_string()),
            license: "Apache-2.0".to_string(),
            description: "Bidirectional encoder representations from transformers".to_string(),
            performance_metrics: Some(PerformanceMetrics {
                accuracy: Some(0.84),
                throughput_items_per_second: Some(5.0),
                latency_ms: Some(200.0),
                memory_usage_mb: Some(4096),
                benchmark_dataset: Some("GLUE".to_string()),
            }),
        });

        // GPT-2 for text generation
        self.register_model(ModelInfo {
            name: "gpt2".to_string(),
            version: "1.0".to_string(),
            category: AICategory::NLP,
            framework: Framework::HuggingFace,
            size_mb: 548,
            hardware_spec: HardwareSpec {
                min_gpu_memory_gb: 6,
                min_cpu_cores: 4,
                min_ram_gb: 8,
                preferred_gpu_types: vec!["RTX 3070".to_string(), "RTX 4070".to_string()],
                supports_cpu_only: true,
                requires_specialized_hardware: false,
                estimated_inference_time_ms: 500,
                max_batch_size: 8,
            },
            supported_tasks: vec!["text_generation".to_string(), "code_generation".to_string()],
            input_formats: vec!["text/plain".to_string()],
            output_formats: vec!["text/plain".to_string()],
            model_url: Some("https://huggingface.co/gpt2".to_string()),
            license: "MIT".to_string(),
            description: "Generative pre-trained transformer for text generation".to_string(),
            performance_metrics: Some(PerformanceMetrics {
                accuracy: None,
                throughput_items_per_second: Some(2.0),
                latency_ms: Some(500.0),
                memory_usage_mb: Some(6144),
                benchmark_dataset: None,
            }),
        });

        // Llama 2 7B for conversational AI
        self.register_model(ModelInfo {
            name: "llama2-7b".to_string(),
            version: "2.0".to_string(),
            category: AICategory::NLP,
            framework: Framework::Ollama,
            size_mb: 3800,
            hardware_spec: HardwareSpec {
                min_gpu_memory_gb: 8,
                min_cpu_cores: 8,
                min_ram_gb: 16,
                preferred_gpu_types: vec!["RTX 3080".to_string(), "RTX 4080".to_string()],
                supports_cpu_only: true,
                requires_specialized_hardware: false,
                estimated_inference_time_ms: 1000,
                max_batch_size: 4,
            },
            supported_tasks: vec![
                "conversational_ai".to_string(),
                "text_generation".to_string(),
                "question_answering".to_string(),
            ],
            input_formats: vec!["text/plain".to_string()],
            output_formats: vec!["text/plain".to_string()],
            model_url: Some("https://ollama.ai/library/llama2".to_string()),
            license: "Custom".to_string(),
            description: "Large language model for conversational AI".to_string(),
            performance_metrics: Some(PerformanceMetrics {
                accuracy: None,
                throughput_items_per_second: Some(1.0),
                latency_ms: Some(1000.0),
                memory_usage_mb: Some(8192),
                benchmark_dataset: None,
            }),
        });
    }

    /// Register audio processing models
    fn register_audio_models(&mut self) {
        // Whisper for speech-to-text
        self.register_model(ModelInfo {
            name: "whisper-base".to_string(),
            version: "1.0".to_string(),
            category: AICategory::Audio,
            framework: Framework::Whisper,
            size_mb: 145,
            hardware_spec: HardwareSpec {
                min_gpu_memory_gb: 2,
                min_cpu_cores: 4,
                min_ram_gb: 4,
                preferred_gpu_types: vec!["RTX 3060".to_string(), "RTX 4060".to_string()],
                supports_cpu_only: true,
                requires_specialized_hardware: false,
                estimated_inference_time_ms: 2000,
                max_batch_size: 8,
            },
            supported_tasks: vec!["speech_to_text".to_string(), "audio_transcription".to_string()],
            input_formats: vec!["audio/wav".to_string(), "audio/mp3".to_string()],
            output_formats: vec!["text/plain".to_string(), "application/json".to_string()],
            model_url: Some("https://github.com/openai/whisper".to_string()),
            license: "MIT".to_string(),
            description: "Automatic speech recognition model".to_string(),
            performance_metrics: Some(PerformanceMetrics {
                accuracy: Some(0.95),
                throughput_items_per_second: Some(0.5),
                latency_ms: Some(2000.0),
                memory_usage_mb: Some(2048),
                benchmark_dataset: Some("LibriSpeech".to_string()),
            }),
        });
    }

    /// Register time series analysis models
    fn register_time_series_models(&mut self) {
        // Prophet for forecasting
        self.register_model(ModelInfo {
            name: "prophet".to_string(),
            version: "1.1".to_string(),
            category: AICategory::TimeSeries,
            framework: Framework::Custom("Prophet".to_string()),
            size_mb: 50,
            hardware_spec: HardwareSpec {
                min_gpu_memory_gb: 0,
                min_cpu_cores: 2,
                min_ram_gb: 4,
                preferred_gpu_types: vec![],
                supports_cpu_only: true,
                requires_specialized_hardware: false,
                estimated_inference_time_ms: 1000,
                max_batch_size: 1,
            },
            supported_tasks: vec!["forecasting".to_string(), "trend_analysis".to_string()],
            input_formats: vec!["application/json".to_string(), "text/csv".to_string()],
            output_formats: vec!["application/json".to_string()],
            model_url: Some("https://facebook.github.io/prophet/".to_string()),
            license: "MIT".to_string(),
            description: "Forecasting model for time series data".to_string(),
            performance_metrics: Some(PerformanceMetrics {
                accuracy: Some(0.85),
                throughput_items_per_second: Some(1.0),
                latency_ms: Some(1000.0),
                memory_usage_mb: Some(512),
                benchmark_dataset: None,
            }),
        });
    }

    /// Register multimodal AI models
    fn register_multimodal_models(&mut self) {
        // CLIP for image-text understanding
        self.register_model(ModelInfo {
            name: "clip-vit-base-patch32".to_string(),
            version: "1.0".to_string(),
            category: AICategory::Multimodal,
            framework: Framework::HuggingFace,
            size_mb: 605,
            hardware_spec: HardwareSpec {
                min_gpu_memory_gb: 4,
                min_cpu_cores: 4,
                min_ram_gb: 8,
                preferred_gpu_types: vec!["RTX 3070".to_string(), "RTX 4070".to_string()],
                supports_cpu_only: true,
                requires_specialized_hardware: false,
                estimated_inference_time_ms: 300,
                max_batch_size: 16,
            },
            supported_tasks: vec![
                "image_captioning".to_string(),
                "visual_question_answering".to_string(),
                "cross_modal_retrieval".to_string(),
            ],
            input_formats: vec!["image/jpeg".to_string(), "text/plain".to_string()],
            output_formats: vec!["application/json".to_string()],
            model_url: Some("https://huggingface.co/openai/clip-vit-base-patch32".to_string()),
            license: "MIT".to_string(),
            description: "Contrastive language-image pre-training model".to_string(),
            performance_metrics: Some(PerformanceMetrics {
                accuracy: Some(0.63),
                throughput_items_per_second: Some(3.3),
                latency_ms: Some(300.0),
                memory_usage_mb: Some(4096),
                benchmark_dataset: Some("ImageNet".to_string()),
            }),
        });
    }

    /// Register reinforcement learning models
    fn register_rl_models(&mut self) {
        // PPO for policy optimization
        self.register_model(ModelInfo {
            name: "ppo-cartpole".to_string(),
            version: "1.0".to_string(),
            category: AICategory::ReinforcementLearning,
            framework: Framework::PyTorch,
            size_mb: 10,
            hardware_spec: HardwareSpec {
                min_gpu_memory_gb: 2,
                min_cpu_cores: 4,
                min_ram_gb: 4,
                preferred_gpu_types: vec!["RTX 3060".to_string()],
                supports_cpu_only: true,
                requires_specialized_hardware: false,
                estimated_inference_time_ms: 10,
                max_batch_size: 1,
            },
            supported_tasks: vec!["policy_optimization".to_string()],
            input_formats: vec!["application/json".to_string()],
            output_formats: vec!["application/json".to_string()],
            model_url: Some("https://stable-baselines3.readthedocs.io/".to_string()),
            license: "MIT".to_string(),
            description: "Proximal Policy Optimization for reinforcement learning".to_string(),
            performance_metrics: Some(PerformanceMetrics {
                accuracy: None,
                throughput_items_per_second: Some(100.0),
                latency_ms: Some(10.0),
                memory_usage_mb: Some(512),
                benchmark_dataset: Some("CartPole-v1".to_string()),
            }),
        });
    }

    /// Register specialized domain models
    fn register_specialized_models(&mut self) {
        // Medical imaging model
        self.register_model(ModelInfo {
            name: "medical-seg-chest-xray".to_string(),
            version: "1.0".to_string(),
            category: AICategory::Specialized,
            framework: Framework::PyTorch,
            size_mb: 250,
            hardware_spec: HardwareSpec {
                min_gpu_memory_gb: 6,
                min_cpu_cores: 4,
                min_ram_gb: 8,
                preferred_gpu_types: vec!["RTX 3070".to_string(), "RTX 4070".to_string()],
                supports_cpu_only: false,
                requires_specialized_hardware: true,
                estimated_inference_time_ms: 800,
                max_batch_size: 8,
            },
            supported_tasks: vec!["medical_imaging".to_string(), "image_segmentation".to_string()],
            input_formats: vec!["image/dicom".to_string(), "image/png".to_string()],
            output_formats: vec!["image/png".to_string(), "application/json".to_string()],
            model_url: Some("https://github.com/Project-MONAI/MONAI".to_string()),
            license: "Apache-2.0".to_string(),
            description: "Medical image segmentation for chest X-rays".to_string(),
            performance_metrics: Some(PerformanceMetrics {
                accuracy: Some(0.92),
                throughput_items_per_second: Some(1.25),
                latency_ms: Some(800.0),
                memory_usage_mb: Some(6144),
                benchmark_dataset: Some("ChestX-ray14".to_string()),
            }),
        });

        // Protein folding model
        self.register_model(ModelInfo {
            name: "alphafold2-lite".to_string(),
            version: "2.0".to_string(),
            category: AICategory::Specialized,
            framework: Framework::TensorFlow,
            size_mb: 1200,
            hardware_spec: HardwareSpec {
                min_gpu_memory_gb: 12,
                min_cpu_cores: 8,
                min_ram_gb: 32,
                preferred_gpu_types: vec!["RTX 3090".to_string(), "RTX 4090".to_string()],
                supports_cpu_only: false,
                requires_specialized_hardware: true,
                estimated_inference_time_ms: 30000,
                max_batch_size: 1,
            },
            supported_tasks: vec!["protein_folding".to_string(), "structure_prediction".to_string()],
            input_formats: vec!["text/fasta".to_string()],
            output_formats: vec!["application/pdb".to_string()],
            model_url: Some("https://github.com/deepmind/alphafold".to_string()),
            license: "Apache-2.0".to_string(),
            description: "Protein structure prediction model".to_string(),
            performance_metrics: Some(PerformanceMetrics {
                accuracy: Some(0.95),
                throughput_items_per_second: Some(0.033),
                latency_ms: Some(30000.0),
                memory_usage_mb: Some(12288),
                benchmark_dataset: Some("CASP14".to_string()),
            }),
        });
    }
}

impl Default for ModelRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_model_registry_creation() {
        let registry = ModelRegistry::new();
        assert!(!registry.get_all_models().is_empty());
    }

    #[test]
    fn test_find_models_by_category() {
        let registry = ModelRegistry::new();
        let cv_models = registry.find_models_by_category(&AICategory::ComputerVision);
        assert!(!cv_models.is_empty());
        
        let nlp_models = registry.find_models_by_category(&AICategory::NLP);
        assert!(!nlp_models.is_empty());
    }

    #[test]
    fn test_find_best_model() {
        let registry = ModelRegistry::new();
        let best_model = registry.find_best_model("object_detection", 4, 4, 8);
        assert!(best_model.is_some());
        assert_eq!(best_model.unwrap().name, "yolov8n");
    }

    #[test]
    fn test_find_models_by_task() {
        let registry = ModelRegistry::new();
        let models = registry.find_models_by_task("text_classification");
        assert!(!models.is_empty());
        
        let speech_models = registry.find_models_by_task("speech_to_text");
        assert!(!speech_models.is_empty());
    }
} 