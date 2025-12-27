//! # Compute Executor
//!
//! This module handles the execution of compute tasks, routing them to the appropriate engine.

use anyhow::Result;
use tracing::{info, warn};
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
                info!(task_id = %task.id, "Executing data pipeline task");
                let result = self.data_executor.execute_sql_job(sql_query, data_source).await?;
                Ok(result)
            }
            // Route all AI and Compute jobs to the Secure Model Executor
            JobType::AIInference { model_type, input_data, .. } => {
                info!(task_id = %task.id, model = %model_type, "Executing confidential AI inference");
                let (result, _quote) = self.model_executor.execute_model_job(model_type, input_data).await?;
                // In a real version, we'd return the quote too, but for now just string result
                Ok(result)
            }
            JobType::Render3D { scene_file, .. } => {
                info!(task_id = %task.id, "Executing confidential render");
                let (result, _) = self.model_executor.execute_model_job("blender-renderer", scene_file).await?;
                Ok(result)
            }
            JobType::ConfidentialVM { image_url, .. } => {
                info!(task_id = %task.id, image = %image_url, "Launching confidential VM");
                let (result, _) = self.model_executor.execute_model_job(image_url, "vm-config").await?;
                Ok(result)
            }
            JobType::Custom { docker_image, .. } => {
                info!(task_id = %task.id, image = %docker_image, "Executing custom confidential container");
                let (result, _) = self.model_executor.execute_model_job(docker_image, "custom-args").await?;
                Ok(result)
            }
            // Fallback for other legacy types to use generic executor or fail
            _ => {
                // Map other types to generic model execution if possible
                warn!(task_id = %task.id, task_type = ?task.task_type, "Generic/legacy task type, routing to default secure runner");
                let (result, _) = self.model_executor.execute_model_job("default-runner", "generic-task").await?;
                Ok(result)
            }
        }
    }
}
