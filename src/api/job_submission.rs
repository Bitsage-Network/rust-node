//! # Job Submission API
//!
//! REST API endpoints for submitting jobs to the BitSage Network

use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    Router, routing::post,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{info, error, debug};

use crate::coordinator::job_processor::JobProcessor;
use crate::node::coordinator::{JobRequest, JobType as CoordinatorJobType};
use crate::compute::job_estimation::JobEstimator;

/// API state
#[derive(Clone)]
pub struct SubmissionApiState {
    pub job_processor: Arc<JobProcessor>,
    pub estimator: Arc<JobEstimator>,
}

impl SubmissionApiState {
    /// Create a new submission API state with default estimator
    pub fn new(job_processor: Arc<JobProcessor>) -> Self {
        Self {
            job_processor,
            estimator: Arc::new(JobEstimator::new()),
        }
    }

    /// Create with custom estimator
    pub fn with_estimator(job_processor: Arc<JobProcessor>, estimator: JobEstimator) -> Self {
        Self {
            job_processor,
            estimator: Arc::new(estimator),
        }
    }
}

/// Job submission request (API format)
#[derive(Debug, Deserialize)]
pub struct SubmitJobRequest {
    pub job_type: String,
    pub priority: Option<u8>,
    pub max_cost: Option<u64>,
    pub deadline: Option<String>,
    pub client_address: String,
    pub callback_url: Option<String>,
    
    // Job-specific fields
    pub model_url: Option<String>,
    pub input_data: Option<String>,
    pub parameters: Option<HashMap<String, serde_json::Value>>,
    pub sql_query: Option<String>,
    pub data_source: Option<String>,
    pub container_image: Option<String>,
    pub encrypted_data: Option<bool>,
    pub require_tee: Option<bool>,
}

/// Job submission response
#[derive(Debug, Serialize)]
pub struct SubmitJobResponse {
    pub job_id: String,
    pub status: String,
    pub message: String,
    pub estimated_cost: Option<u64>,
    pub estimated_duration_secs: Option<u64>,
}

/// Create submission API router
pub fn create_submission_router(state: SubmissionApiState) -> Router {
    Router::new()
        .route("/api/submit", post(submit_job))
        .route("/api/submit/batch", post(submit_batch_jobs))
        .with_state(state)
}

/// Submit a single job
async fn submit_job(
    State(state): State<SubmissionApiState>,
    Json(payload): Json<SubmitJobRequest>,
) -> Result<Json<SubmitJobResponse>, (StatusCode, String)> {
    info!("Received job submission: {:?}", payload.job_type);

    let priority = payload.priority.unwrap_or(5);

    // Parse job type and create job request
    let job_request = match parse_job_request(payload) {
        Ok(req) => req,
        Err(e) => {
            error!("Failed to parse job request: {}", e);
            return Err((StatusCode::BAD_REQUEST, e));
        }
    };

    // Estimate cost and duration before submission
    let estimate = state.estimator.estimate(&job_request.job_type, priority);
    debug!(
        "Job estimate: duration={}s, cost={}, tasks={}, gpu={}",
        estimate.duration_secs,
        estimate.cost_formatted,
        estimate.estimated_tasks,
        estimate.requires_gpu
    );

    // Submit job to processor
    let job_id = state.job_processor.submit_job(job_request).await
        .map_err(|e| {
            error!("Failed to submit job: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        })?;

    info!(
        "Job {} submitted successfully (estimated: {}s, {})",
        job_id, estimate.duration_secs, estimate.cost_formatted
    );

    Ok(Json(SubmitJobResponse {
        job_id: job_id.to_string(),
        status: "submitted".to_string(),
        message: format!(
            "Job submitted successfully. Estimated {} tasks, requires GPU: {}",
            estimate.estimated_tasks, estimate.requires_gpu
        ),
        estimated_cost: Some(estimate.cost_wei as u64),
        estimated_duration_secs: Some(estimate.duration_secs),
    }))
}

/// Submit multiple jobs as a batch
async fn submit_batch_jobs(
    State(state): State<SubmissionApiState>,
    Json(payload): Json<Vec<SubmitJobRequest>>,
) -> Result<Json<Vec<SubmitJobResponse>>, (StatusCode, String)> {
    info!("Received batch submission with {} jobs", payload.len());

    if payload.len() > 100 {
        return Err((StatusCode::BAD_REQUEST, "Batch size exceeds maximum of 100 jobs".to_string()));
    }

    let mut responses = Vec::new();

    for job_payload in payload {
        let priority = job_payload.priority.unwrap_or(5);

        match parse_job_request(job_payload) {
            Ok(job_request) => {
                // Estimate cost and duration
                let estimate = state.estimator.estimate(&job_request.job_type, priority);

                match state.job_processor.submit_job(job_request).await {
                    Ok(job_id) => {
                        responses.push(SubmitJobResponse {
                            job_id: job_id.to_string(),
                            status: "submitted".to_string(),
                            message: format!(
                                "Job submitted. Est. {} tasks, GPU: {}",
                                estimate.estimated_tasks, estimate.requires_gpu
                            ),
                            estimated_cost: Some(estimate.cost_wei as u64),
                            estimated_duration_secs: Some(estimate.duration_secs),
                        });
                    },
                    Err(e) => {
                        error!("Failed to submit job in batch: {}", e);
                        responses.push(SubmitJobResponse {
                            job_id: "error".to_string(),
                            status: "failed".to_string(),
                            message: format!("Failed to submit: {}", e),
                            estimated_cost: None,
                            estimated_duration_secs: None,
                        });
                    }
                }
            },
            Err(e) => {
                error!("Failed to parse job in batch: {}", e);
                responses.push(SubmitJobResponse {
                    job_id: "error".to_string(),
                    status: "failed".to_string(),
                    message: format!("Invalid request: {}", e),
                    estimated_cost: None,
                    estimated_duration_secs: None,
                });
            }
        }
    }

    Ok(Json(responses))
}

/// Parse API job request into internal job request
fn parse_job_request(payload: SubmitJobRequest) -> Result<JobRequest, String> {
    let job_type = match payload.job_type.to_lowercase().as_str() {
        "ai_inference" | "aiinference" => {
            let model_type = payload.model_url
                .ok_or_else(|| "model_url required for AI inference jobs".to_string())?;
            let input_data_str = payload.input_data.unwrap_or_default();
            let parameters = payload.parameters.unwrap_or_default();
            
            CoordinatorJobType::AIInference {
                model_type,
                input_data: input_data_str,
                batch_size: 1,
                parameters,
            }
        },
        "data_pipeline" | "datapipeline" | "sql" => {
            let sql_query = payload.sql_query
                .ok_or_else(|| "sql_query required for data pipeline jobs".to_string())?;
            let data_source = payload.data_source
                .ok_or_else(|| "data_source required for data pipeline jobs".to_string())?;
            let tee_required = payload.require_tee.unwrap_or(false);
            
            CoordinatorJobType::DataPipeline {
                sql_query,
                data_source,
                tee_required,
            }
        },
        "confidential_vm" | "confidentialvm" | "vm" => {
            let image_url = payload.container_image
                .ok_or_else(|| "container_image required for confidential VM jobs".to_string())?;
            
            CoordinatorJobType::ConfidentialVM {
                image_url,
                memory_mb: 4096,
                vcpu_count: 2,
                tee_type: "TDX".to_string(),
            }
        },
        "rendering" | "3d_rendering" => {
            CoordinatorJobType::Render3D {
                scene_file: payload.model_url.unwrap_or_default(),
                output_resolution: (1920, 1080),
                frames: Some(1),
                quality_preset: "medium".to_string(),
            }
        },
        _ => {
            return Err(format!("Unknown job type: {}", payload.job_type));
        }
    };
    
    let deadline = if let Some(deadline_str) = payload.deadline {
        Some(chrono::DateTime::parse_from_rfc3339(&deadline_str)
            .map_err(|e| format!("Invalid deadline format: {}", e))?
            .with_timezone(&chrono::Utc))
    } else {
        None
    };
    
    Ok(JobRequest {
        job_type,
        priority: payload.priority.unwrap_or(5),
        max_cost: payload.max_cost.unwrap_or(10000),
        deadline,
        client_address: payload.client_address,
        callback_url: payload.callback_url,
        data: vec![], // Already embedded in job_type
        max_duration_secs: 3600, // Default 1 hour
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_ai_inference_job() {
        let payload = SubmitJobRequest {
            job_type: "ai_inference".to_string(),
            priority: Some(5),
            max_cost: Some(1000),
            deadline: None,
            client_address: "0x123".to_string(),
            callback_url: None,
            model_url: Some("https://example.com/model".to_string()),
            input_data: Some("test input".to_string()),
            parameters: Some(HashMap::new()),
            sql_query: None,
            data_source: None,
            container_image: None,
            encrypted_data: None,
            require_tee: None,
        };
        
        let result = parse_job_request(payload);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_parse_data_pipeline_job() {
        let payload = SubmitJobRequest {
            job_type: "data_pipeline".to_string(),
            priority: Some(5),
            max_cost: Some(1000),
            deadline: None,
            client_address: "0x123".to_string(),
            callback_url: None,
            model_url: None,
            input_data: None,
            parameters: None,
            sql_query: Some("SELECT * FROM table".to_string()),
            data_source: Some("s3://bucket/data.parquet".to_string()),
            container_image: None,
            encrypted_data: None,
            require_tee: None,
        };
        
        let result = parse_job_request(payload);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_parse_invalid_job_type() {
        let payload = SubmitJobRequest {
            job_type: "invalid_type".to_string(),
            priority: Some(5),
            max_cost: Some(1000),
            deadline: None,
            client_address: "0x123".to_string(),
            callback_url: None,
            model_url: None,
            input_data: None,
            parameters: None,
            sql_query: None,
            data_source: None,
            container_image: None,
            encrypted_data: None,
            require_tee: None,
        };
        
        let result = parse_job_request(payload);
        assert!(result.is_err());
    }
}

