//! # Compute Executor
//!
//! This module handles the execution of compute tasks, routing them to the appropriate engine.

use anyhow::{Result, anyhow};
use crate::node::coordinator::JobType;
use crate::node::coordinator::Task;
use crate::compute::data_executor::SecureDataExecutor;
use crate::compute::model_executor::SecureModelExecutor;
use std::sync::Arc;

/// Compute executor for running tasks
pub struct ComputeExecutor {
    data_executor: Arc<SecureDataExecutor>,
    model_executor: Arc<SecureModelExecutor>,
}

impl ComputeExecutor {
    /// Create a new compute executor
    pub fn new() -> Self {
        Self {
            data_executor: Arc::new(SecureDataExecutor::new()),
            model_executor: Arc::new(SecureModelExecutor::new()),
        }
    }

    /// Execute a compute task
    pub async fn execute_task(&self, task: &Task) -> Result<String> {
        match &task.task_type {
            JobType::DataPipeline { sql_query, data_source, .. } => {
                // Route to Secure Data Executor (DataFusion)
                println!("🔒 Executing Data Pipeline Task: {}", task.id);
                let result = self.data_executor.execute_sql_job(sql_query, data_source).await?;
                Ok(result)
            }
            // Route all AI and Compute jobs to the Secure Model Executor
            JobType::AIInference { model_type, input_data, .. } => {
                println!("🤖 Executing Confidential AI Inference: {}", task.id);
                let (result, _quote) = self.model_executor.execute_model_job(model_type, input_data).await?;
                // In a real version, we'd return the quote too, but for now just string result
                Ok(result)
            }
            JobType::Render3D { scene_file, .. } => {
                println!("🎨 Executing Confidential Render: {}", task.id);
                let (result, _) = self.model_executor.execute_model_job("blender-renderer", scene_file).await?;
                Ok(result)
            }
            JobType::ConfidentialVM { image_url, .. } => {
                println!("💻 Launching Confidential VM: {}", task.id);
                let (result, _) = self.model_executor.execute_model_job(image_url, "vm-config").await?;
                Ok(result)
            }
            JobType::Custom { docker_image, .. } => {
                println!("📦 Executing Custom Confidential Container: {}", task.id);
                let (result, _) = self.model_executor.execute_model_job(docker_image, "custom-args").await?;
                Ok(result)
            }
            // Fallback for other legacy types to use generic executor or fail
            _ => {
                // Map other types to generic model execution if possible
                println!("⚠️ Generic/Legacy Task Type: {:?} - Routing to Default Secure Runner", task.task_type);
                let (result, _) = self.model_executor.execute_model_job("default-runner", "generic-task").await?;
                Ok(result)
            }
        }
    }
}
