//! # Job Monitoring API
//!
//! REST API endpoints for real-time job monitoring and result collection

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Json, sse::{Event, KeepAlive, Sse}},
    Router, routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::sync::Arc;
use tokio_stream::Stream;
use tokio::time::{Duration, interval};
use tracing::{info, error};

use std::str::FromStr;

use crate::types::JobId;
use crate::coordinator::job_processor::{JobProcessor, JobInfo};
use crate::node::coordinator::JobStatus;

/// API state
#[derive(Clone)]
pub struct MonitoringApiState {
    pub job_processor: Arc<JobProcessor>,
}

/// Query parameters for listing jobs
#[derive(Debug, Deserialize)]
pub struct ListJobsQuery {
    pub status: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// Job status response
#[derive(Debug, Serialize)]
pub struct JobStatusResponse {
    pub job_id: String,
    pub status: String,
    pub progress: f32,
    pub created_at: u64,
    pub started_at: Option<u64>,
    pub completed_at: Option<u64>,
    pub execution_time_ms: Option<u64>,
    pub assigned_worker: Option<String>,
    pub retry_count: u32,
    pub error_message: Option<String>,
}

/// Job result response
#[derive(Debug, Serialize)]
pub struct JobResultResponse {
    pub job_id: String,
    pub status: String,
    pub completed_tasks: u32,
    pub total_tasks: u32,
    pub output_files: Vec<String>,
    pub execution_time_ms: u64,
    pub total_cost: u64,
    pub error_message: Option<String>,
}

/// Job list response
#[derive(Debug, Serialize)]
pub struct JobListResponse {
    pub jobs: Vec<JobStatusResponse>,
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
}

/// Statistics response
#[derive(Debug, Serialize)]
pub struct StatsResponse {
    pub total_jobs: u64,
    pub active_jobs: u64,
    pub completed_jobs: u64,
    pub failed_jobs: u64,
    pub avg_execution_time_ms: u64,
    pub total_execution_time_ms: u64,
}

/// Create monitoring API router
pub fn create_monitoring_router(state: MonitoringApiState) -> Router {
    Router::new()
        .route("/api/jobs", get(list_jobs))
        .route("/api/jobs/:job_id", get(get_job_status))
        .route("/api/jobs/:job_id/result", get(get_job_result))
        .route("/api/jobs/:job_id/cancel", post(cancel_job))
        .route("/api/jobs/:job_id/stream", get(stream_job_status))
        .route("/api/stats", get(get_stats))
        .route("/api/health", get(health_check))
        .with_state(state)
}

/// List all jobs with optional filtering
async fn list_jobs(
    State(state): State<MonitoringApiState>,
    Query(params): Query<ListJobsQuery>,
) -> Result<Json<JobListResponse>, (StatusCode, String)> {
    info!("Listing jobs with params: {:?}", params);
    
    let limit = params.limit.unwrap_or(50).min(100);
    let offset = params.offset.unwrap_or(0);
    
    // Get all jobs from processor
    let all_jobs = state.job_processor.list_jobs().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // Filter by status if specified
    let filtered_jobs: Vec<_> = if let Some(status_filter) = params.status {
        all_jobs.into_iter()
            .filter(|job| format!("{:?}", job.status).eq_ignore_ascii_case(&status_filter))
            .collect()
    } else {
        all_jobs
    };
    
    let total = filtered_jobs.len();
    
    // Apply pagination
    let paginated_jobs: Vec<_> = filtered_jobs.into_iter()
        .skip(offset)
        .take(limit)
        .collect();
    
    // Convert to response format
    let jobs: Vec<JobStatusResponse> = paginated_jobs.into_iter()
        .map(|job| job_info_to_response(&job))
        .collect();
    
    Ok(Json(JobListResponse {
        jobs,
        total,
        offset,
        limit,
    }))
}

/// Get status of a specific job
async fn get_job_status(
    State(state): State<MonitoringApiState>,
    Path(job_id): Path<String>,
) -> Result<Json<JobStatusResponse>, (StatusCode, String)> {
    info!("Getting status for job: {}", job_id);
    
    let job_id = JobId::from_str(&job_id)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid job ID: {}", e)))?;
    
    let job_info = state.job_processor.get_job_details(job_id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Job not found".to_string()))?;
    
    Ok(Json(job_info_to_response(&job_info)))
}

/// Get result of a completed job
async fn get_job_result(
    State(state): State<MonitoringApiState>,
    Path(job_id): Path<String>,
) -> Result<Json<JobResultResponse>, (StatusCode, String)> {
    info!("Getting result for job: {}", job_id);
    
    let job_id = JobId::from_str(&job_id)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid job ID: {}", e)))?;
    
    let job_info = state.job_processor.get_job_details(job_id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Job not found".to_string()))?;
    
    // Check if job is completed
    if job_info.status != JobStatus::Completed {
        return Err((StatusCode::BAD_REQUEST, format!("Job is not completed yet (status: {:?})", job_info.status)));
    }
    
    // Extract result from execution state
    let result = match job_info.execution_state {
        crate::coordinator::job_processor::JobExecutionState::Completed(ref result) => result.clone(),
        _ => return Err((StatusCode::INTERNAL_SERVER_ERROR, "Job completed but no result found".to_string())),
    };
    
    Ok(Json(JobResultResponse {
        job_id: job_id.to_string(),
        status: format!("{:?}", result.status),
        completed_tasks: result.completed_tasks,
        total_tasks: result.total_tasks,
        output_files: result.output_files,
        execution_time_ms: result.execution_time,
        total_cost: result.total_cost,
        error_message: result.error_message,
    }))
}

/// Cancel a running job
async fn cancel_job(
    State(state): State<MonitoringApiState>,
    Path(job_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    info!("Cancelling job: {}", job_id);
    
    let job_id = JobId::from_str(&job_id)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid job ID: {}", e)))?;
    
    state.job_processor.cancel_job(job_id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Job cancelled successfully"
    })))
}

/// Stream real-time job status updates using Server-Sent Events
async fn stream_job_status(
    State(state): State<MonitoringApiState>,
    Path(job_id): Path<String>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, (StatusCode, String)> {
    info!("Starting SSE stream for job: {}", job_id);
    
    let job_id = JobId::from_str(&job_id)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid job ID: {}", e)))?;
    
    // Verify job exists
    let _ = state.job_processor.get_job_details(job_id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Job not found".to_string()))?;
    
    // Create stream
    let stream = async_stream::stream! {
        let mut ticker = interval(Duration::from_secs(1));
        
        loop {
            ticker.tick().await;
            
            // Get current job status
            match state.job_processor.get_job_details(job_id).await {
                Ok(Some(job_info)) => {
                    let response = job_info_to_response(&job_info);
                    let json = serde_json::to_string(&response).unwrap_or_default();
                    
                    yield Ok(Event::default().data(json));
                    
                    // Stop streaming if job is in terminal state
                    if matches!(job_info.status, JobStatus::Completed | JobStatus::Failed | JobStatus::Cancelled) {
                        break;
                    }
                },
                Ok(None) => {
                    yield Ok(Event::default().data("{\"error\":\"Job not found\"}"));
                    break;
                },
                Err(e) => {
                    error!("Error streaming job status: {}", e);
                    yield Ok(Event::default().data(format!("{{\"error\":\"{}\"}}", e)));
                    break;
                }
            }
        }
    };
    
    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

/// Get system statistics
async fn get_stats(
    State(state): State<MonitoringApiState>,
) -> Result<Json<StatsResponse>, (StatusCode, String)> {
    info!("Getting system statistics");
    
    let stats = state.job_processor.get_stats().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    Ok(Json(StatsResponse {
        total_jobs: stats.total_jobs,
        active_jobs: stats.active_jobs,
        completed_jobs: stats.completed_jobs,
        failed_jobs: stats.failed_jobs,
        avg_execution_time_ms: stats.average_completion_time_secs * 1000,
        total_execution_time_ms: stats.total_jobs * stats.average_completion_time_secs * 1000,
    }))
}

/// Health check endpoint
async fn health_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().timestamp(),
        "version": env!("CARGO_PKG_VERSION")
    }))
}

/// Convert JobInfo to API response format
fn job_info_to_response(job: &JobInfo) -> JobStatusResponse {
    let execution_time_ms = if let (Some(started), Some(completed)) = (job.started_at, job.completed_at) {
        Some(completed.saturating_sub(started) * 1000)
    } else {
        None
    };
    
    let progress = calculate_progress(job);
    
    let error_message = match &job.execution_state {
        crate::coordinator::job_processor::JobExecutionState::Failed(msg) => Some(msg.clone()),
        crate::coordinator::job_processor::JobExecutionState::Completed(result) => result.error_message.clone(),
        _ => None,
    };
    
    JobStatusResponse {
        job_id: job.id.to_string(),
        status: format!("{:?}", job.status),
        progress,
        created_at: job.created_at,
        started_at: job.started_at,
        completed_at: job.completed_at,
        execution_time_ms,
        assigned_worker: job.assigned_worker.map(|w| w.to_string()),
        retry_count: job.retry_count,
        error_message,
    }
}

/// Calculate job progress (0.0 to 1.0)
fn calculate_progress(job: &JobInfo) -> f32 {
    match job.status {
        JobStatus::Pending | JobStatus::Submitted => 0.0,
        JobStatus::Analyzing | JobStatus::Queued => 0.1,
        JobStatus::Running => {
            // Estimate progress based on elapsed time vs timeout
            if let Some(started) = job.started_at {
                let elapsed = chrono::Utc::now().timestamp() as u64 - started;
                let timeout = job.timeout_secs;
                (elapsed as f32 / timeout as f32).min(0.9)
            } else {
                0.2
            }
        },
        JobStatus::Assembling => 0.95,
        JobStatus::Completed => 1.0,
        JobStatus::Failed | JobStatus::Cancelled => 0.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::coordinator::JobResult;

    #[tokio::test]
    async fn test_health_check() {
        let response = health_check().await;
        assert_eq!(response.0["status"], "healthy");
    }
    
    #[test]
    fn test_calculate_progress() {
        let job = JobInfo {
            id: JobId::new(),
            request: create_test_request(),
            status: JobStatus::Completed,
            execution_state: crate::coordinator::job_processor::JobExecutionState::Completed(
                create_test_result()
            ),
            created_at: 1000,
            started_at: Some(1100),
            completed_at: Some(1200),
            assigned_worker: None,
            retry_count: 0,
            max_retries: 3,
            timeout_secs: 300,
            priority: 5,
            tags: vec![],
        };
        
        assert_eq!(calculate_progress(&job), 1.0);
    }
    
    fn create_test_request() -> crate::node::coordinator::JobRequest {
        crate::node::coordinator::JobRequest {
            job_type: crate::node::coordinator::JobType::AIInference {
                model_type: "test".to_string(),
                input_data: "test_data".to_string(),
                batch_size: 1,
                parameters: Default::default(),
            },
            priority: 5,
            max_cost: 1000,
            deadline: None,
            client_address: "0x123".to_string(),
            callback_url: None,
            data: vec![],
            max_duration_secs: 300,
            customer_pubkey: None,
        }
    }

    fn create_test_result() -> JobResult {
        JobResult {
            job_id: JobId::new(),
            status: JobStatus::Completed,
            completed_tasks: 1,
            total_tasks: 1,
            output_files: vec![],
            execution_time: 100,
            total_cost: 50,
            error_message: None,
            proof_hash: None,
            proof_attestation: None,
            proof_commitment: None,
            compressed_proof: None,
            proof_size_bytes: None,
            proof_time_ms: None,
        }
    }
}

