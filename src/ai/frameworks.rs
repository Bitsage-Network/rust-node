//! AI Framework Integrations
//!
//! This module provides abstractions and integrations for different AI frameworks,
//! handling model loading, execution, and resource management.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use anyhow::{Result, anyhow};
use crate::ai::model_registry::{Framework, ModelInfo, AICategory};

/// Framework execution environment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkEnvironment {
    pub framework: Framework,
    pub docker_image: String,
    pub base_command: Vec<String>,
    pub environment_variables: HashMap<String, String>,
    pub required_files: Vec<String>,
    pub supported_categories: Vec<AICategory>,
    pub gpu_support: bool,
    pub cpu_support: bool,
}

/// Framework manager for handling different AI frameworks
pub struct FrameworkManager {
    environments: HashMap<Framework, FrameworkEnvironment>,
}

impl FrameworkManager {
    /// Create a new framework manager with default environments
    pub fn new() -> Self {
        let mut manager = Self {
            environments: HashMap::new(),
        };

        manager.register_default_environments();
        manager
    }

    /// Register a framework environment
    pub fn register_environment(&mut self, env: FrameworkEnvironment) {
        self.environments.insert(env.framework.clone(), env);
    }

    /// Get framework environment
    pub fn get_environment(&self, framework: &Framework) -> Option<&FrameworkEnvironment> {
        self.environments.get(framework)
    }

    /// Get all supported frameworks
    pub fn get_supported_frameworks(&self) -> Vec<&Framework> {
        self.environments.keys().collect()
    }

    /// Check if a framework supports a specific category
    pub fn supports_category(&self, framework: &Framework, category: &AICategory) -> bool {
        self.environments
            .get(framework)
            .map(|env| env.supported_categories.contains(category))
            .unwrap_or(false)
    }

    /// Generate Docker command for model execution
    pub fn generate_docker_command(
        &self,
        model: &ModelInfo,
        input_data: &str,
        output_path: &str,
        gpu_enabled: bool,
    ) -> Result<Vec<String>> {
        let env = self.get_environment(&model.framework)
            .ok_or_else(|| anyhow!("Unsupported framework: {:?}", model.framework))?;

        let mut command = vec!["docker".to_string(), "run".to_string()];

        // Add GPU support if available and requested
        if gpu_enabled && env.gpu_support {
            command.extend(vec![
                "--gpus".to_string(),
                "all".to_string(),
            ]);
        }

        // Add environment variables
        for (key, value) in &env.environment_variables {
            command.extend(vec![
                "-e".to_string(),
                format!("{}={}", key, value),
            ]);
        }

        // Add volume mounts
        command.extend(vec![
            "-v".to_string(),
            format!("{}:/input", input_data),
            "-v".to_string(),
            format!("{}:/output", output_path),
        ]);

        // Add Docker image
        command.push(env.docker_image.clone());

        // Add base command
        command.extend(env.base_command.clone());

        // Add model-specific parameters
        command.extend(self.generate_model_parameters(model)?);

        Ok(command)
    }

    /// Generate model-specific parameters
    fn generate_model_parameters(&self, model: &ModelInfo) -> Result<Vec<String>> {
        let mut params = Vec::new();

        match model.framework {
            Framework::PyTorch => {
                params.extend(vec![
                    "--model".to_string(),
                    model.name.clone(),
                    "--input".to_string(),
                    "/input".to_string(),
                    "--output".to_string(),
                    "/output".to_string(),
                ]);
            }
            Framework::HuggingFace => {
                params.extend(vec![
                    "--model-name".to_string(),
                    model.name.clone(),
                    "--task".to_string(),
                    model.supported_tasks.first().unwrap_or(&"inference".to_string()).clone(),
                    "--input-dir".to_string(),
                    "/input".to_string(),
                    "--output-dir".to_string(),
                    "/output".to_string(),
                ]);
            }
            Framework::Ollama => {
                params.extend(vec![
                    "run".to_string(),
                    model.name.clone(),
                    "--input".to_string(),
                    "/input".to_string(),
                    "--output".to_string(),
                    "/output".to_string(),
                ]);
            }
            Framework::Whisper => {
                params.extend(vec![
                    "--model".to_string(),
                    model.name.clone(),
                    "--input".to_string(),
                    "/input".to_string(),
                    "--output".to_string(),
                    "/output".to_string(),
                    "--output-format".to_string(),
                    "json".to_string(),
                ]);
            }
            Framework::StableDiffusion => {
                params.extend(vec![
                    "--model".to_string(),
                    model.name.clone(),
                    "--prompt-file".to_string(),
                    "/input/prompt.txt".to_string(),
                    "--output".to_string(),
                    "/output/generated.png".to_string(),
                    "--steps".to_string(),
                    "50".to_string(),
                ]);
            }
            _ => {
                // Generic parameters for other frameworks
                params.extend(vec![
                    "--model".to_string(),
                    model.name.clone(),
                    "--input".to_string(),
                    "/input".to_string(),
                    "--output".to_string(),
                    "/output".to_string(),
                ]);
            }
        }

        Ok(params)
    }

    /// Register default framework environments
    fn register_default_environments(&mut self) {
        // PyTorch environment
        self.register_environment(FrameworkEnvironment {
            framework: Framework::PyTorch,
            docker_image: "pytorch/pytorch:2.0.1-cuda11.7-cudnn8-runtime".to_string(),
            base_command: vec!["python".to_string(), "/app/inference.py".to_string()],
            environment_variables: HashMap::from([
                ("PYTHONPATH".to_string(), "/app".to_string()),
                ("CUDA_VISIBLE_DEVICES".to_string(), "0".to_string()),
            ]),
            required_files: vec!["inference.py".to_string(), "requirements.txt".to_string()],
            supported_categories: vec![
                AICategory::ComputerVision,
                AICategory::NLP,
                AICategory::Audio,
                AICategory::ReinforcementLearning,
                AICategory::Specialized,
            ],
            gpu_support: true,
            cpu_support: true,
        });

        // TensorFlow environment
        self.register_environment(FrameworkEnvironment {
            framework: Framework::TensorFlow,
            docker_image: "tensorflow/tensorflow:2.13.0-gpu".to_string(),
            base_command: vec!["python".to_string(), "/app/inference.py".to_string()],
            environment_variables: HashMap::from([
                ("PYTHONPATH".to_string(), "/app".to_string()),
                ("TF_CPP_MIN_LOG_LEVEL".to_string(), "2".to_string()),
            ]),
            required_files: vec!["inference.py".to_string(), "requirements.txt".to_string()],
            supported_categories: vec![
                AICategory::ComputerVision,
                AICategory::NLP,
                AICategory::TimeSeries,
                AICategory::Specialized,
            ],
            gpu_support: true,
            cpu_support: true,
        });

        // HuggingFace Transformers environment
        self.register_environment(FrameworkEnvironment {
            framework: Framework::HuggingFace,
            docker_image: "huggingface/transformers-pytorch-gpu:4.21.0".to_string(),
            base_command: vec!["python".to_string(), "/app/hf_inference.py".to_string()],
            environment_variables: HashMap::from([
                ("TRANSFORMERS_CACHE".to_string(), "/cache".to_string()),
                ("HF_HOME".to_string(), "/cache".to_string()),
            ]),
            required_files: vec!["hf_inference.py".to_string()],
            supported_categories: vec![
                AICategory::NLP,
                AICategory::ComputerVision,
                AICategory::Multimodal,
                AICategory::Audio,
            ],
            gpu_support: true,
            cpu_support: true,
        });

        // Ollama environment
        self.register_environment(FrameworkEnvironment {
            framework: Framework::Ollama,
            docker_image: "ollama/ollama:latest".to_string(),
            base_command: vec!["ollama".to_string()],
            environment_variables: HashMap::from([
                ("OLLAMA_HOST".to_string(), "0.0.0.0".to_string()),
                ("OLLAMA_MODELS".to_string(), "/models".to_string()),
            ]),
            required_files: vec![],
            supported_categories: vec![
                AICategory::NLP,
                AICategory::Multimodal,
            ],
            gpu_support: true,
            cpu_support: true,
        });

        // Whisper environment
        self.register_environment(FrameworkEnvironment {
            framework: Framework::Whisper,
            docker_image: "openai/whisper:latest".to_string(),
            base_command: vec!["whisper".to_string()],
            environment_variables: HashMap::new(),
            required_files: vec![],
            supported_categories: vec![
                AICategory::Audio,
            ],
            gpu_support: true,
            cpu_support: true,
        });

        // Stable Diffusion environment
        self.register_environment(FrameworkEnvironment {
            framework: Framework::StableDiffusion,
            docker_image: "stabilityai/stable-diffusion:latest".to_string(),
            base_command: vec!["python".to_string(), "/app/generate.py".to_string()],
            environment_variables: HashMap::from([
                ("PYTHONPATH".to_string(), "/app".to_string()),
                ("SD_CACHE_DIR".to_string(), "/cache".to_string()),
            ]),
            required_files: vec!["generate.py".to_string()],
            supported_categories: vec![
                AICategory::ComputerVision,
            ],
            gpu_support: true,
            cpu_support: false,
        });

        // ONNX Runtime environment
        self.register_environment(FrameworkEnvironment {
            framework: Framework::ONNX,
            docker_image: "mcr.microsoft.com/onnxruntime/server:latest".to_string(),
            base_command: vec!["onnxruntime_server".to_string()],
            environment_variables: HashMap::new(),
            required_files: vec![],
            supported_categories: vec![
                AICategory::ComputerVision,
                AICategory::NLP,
                AICategory::Audio,
            ],
            gpu_support: true,
            cpu_support: true,
        });
    }
}

impl Default for FrameworkManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Framework-specific execution context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionContext {
    pub framework: Framework,
    pub model_name: String,
    pub input_path: String,
    pub output_path: String,
    pub gpu_enabled: bool,
    pub batch_size: u32,
    pub timeout_seconds: u32,
    pub additional_params: HashMap<String, String>,
}

impl ExecutionContext {
    /// Create a new execution context
    pub fn new(
        framework: Framework,
        model_name: String,
        input_path: String,
        output_path: String,
    ) -> Self {
        Self {
            framework,
            model_name,
            input_path,
            output_path,
            gpu_enabled: true,
            batch_size: 1,
            timeout_seconds: 300,
            additional_params: HashMap::new(),
        }
    }

    /// Set GPU usage
    pub fn with_gpu(mut self, enabled: bool) -> Self {
        self.gpu_enabled = enabled;
        self
    }

    /// Set batch size
    pub fn with_batch_size(mut self, batch_size: u32) -> Self {
        self.batch_size = batch_size;
        self
    }

    /// Set timeout
    pub fn with_timeout(mut self, timeout_seconds: u32) -> Self {
        self.timeout_seconds = timeout_seconds;
        self
    }

    /// Add additional parameter
    pub fn with_param(mut self, key: String, value: String) -> Self {
        self.additional_params.insert(key, value);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_framework_manager_creation() {
        let manager = FrameworkManager::new();
        assert!(!manager.get_supported_frameworks().is_empty());
    }

    #[test]
    fn test_framework_support() {
        let manager = FrameworkManager::new();
        assert!(manager.supports_category(&Framework::PyTorch, &AICategory::ComputerVision));
        assert!(manager.supports_category(&Framework::HuggingFace, &AICategory::NLP));
        assert!(manager.supports_category(&Framework::Whisper, &AICategory::Audio));
    }

    #[test]
    fn test_execution_context() {
        let context = ExecutionContext::new(
            Framework::PyTorch,
            "yolov8n".to_string(),
            "/input".to_string(),
            "/output".to_string(),
        )
        .with_gpu(true)
        .with_batch_size(16)
        .with_timeout(600);

        assert_eq!(context.framework, Framework::PyTorch);
        assert_eq!(context.model_name, "yolov8n");
        assert_eq!(context.gpu_enabled, true);
        assert_eq!(context.batch_size, 16);
        assert_eq!(context.timeout_seconds, 600);
    }
} 